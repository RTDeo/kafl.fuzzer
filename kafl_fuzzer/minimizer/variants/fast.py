import logging
import multiprocessing
import time

from kafl_fuzzer.common.util import filter_available_cpus
from kafl_fuzzer.minimizer.core import (
    Worker,
    graceful_exit,
    load_payload,
    create_chunk_offsets,
    create_complement_payload,
    reset_shared_state,
    save_payload
)

log = logging.getLogger(__name__)


def minimize(config):
    log.info("Hello")
    payload = load_payload(config)

    avail, _ = filter_available_cpus()
    assert config.processes <= len(avail), "Not enough vCPUs available"

    number_of_workers = config.processes

    # Move the payload to a shared memory region so that all workers can access it
    payload = multiprocessing.Array("B", payload)

    # main -> worker
    job_queue: multiprocessing.Queue[tuple[int, int]] = multiprocessing.Queue()

    # worker -> main
    # (crash_offset_start, crash_offset_end)
    shared_result = multiprocessing.Array("i", [-1, -1])  # [-1, -1] if no crash found, otherwise offset
    shared_number_of_completed_jobs = multiprocessing.Value("i", 0)  # number of completed jobs
    shared_payload_size = multiprocessing.Value("I", len(payload))

    workers: list[Worker] = [
        Worker(
            worker_id=worker_id,
            qemu_config=config,
            payload=payload,
            payload_size=shared_payload_size,
            input_queue=job_queue,
            result=shared_result,
            number_of_completed_jobs=shared_number_of_completed_jobs,
        )
        for worker_id in range(number_of_workers)
    ]

    for worker in workers:
        worker.start()

    granularity = 1
    iteration_counter = 1
    initial_payload_size = len(payload)
    taken_jobs = 0
    try:
        while True:
            # prepare jobs and queue
            jobs: list[tuple[int, int]] = create_chunk_offsets(shared_payload_size.value, granularity)  # calculate offsets
            number_of_jobs = len(jobs)
            for job in jobs:  # enqueue offsets
                job_queue.put(job)
            log.info(f"Starting iteration {iteration_counter} with {number_of_jobs} jobs")

            # wait until crash is found or all jobs are done
            time_delta = 0
            while True:
                if number_of_jobs == shared_number_of_completed_jobs.value or not (shared_result[0] == -1 and shared_result[1] == -1):
                    print(f"[MAIN]: Finished iteration {iteration_counter}, {shared_number_of_completed_jobs.value}/{number_of_jobs} jobs done, crash found: {shared_result[:]}")
                    break
                time.sleep(0.1)
                if time_delta >= 1.0:
                    time_delta = 0
                    print(f"[MAIN]: Stats: {number_of_jobs - shared_number_of_completed_jobs.value}/{number_of_jobs} jobs left | Granularity: {granularity} | Payload size: {shared_payload_size.value}/{initial_payload_size} | Chunk size: {shared_payload_size.value//granularity}")
                time_delta += 0.1

            # clear queue before next iteration
            while not job_queue.empty():
                job_queue.get()
                taken_jobs += 1

            # Check if all workers finished
            while (shared_number_of_completed_jobs.value + taken_jobs) != number_of_jobs:
                time.sleep(0.1)
                if time_delta >= 1.0:
                    time_delta = 0
                    print(f"[MAIN]: Waiting for workers to finish: {shared_number_of_completed_jobs.value + taken_jobs}/{number_of_jobs}")
                time_delta += 0.1

            # check if scripts work is done
            if granularity == shared_payload_size.value and shared_result[0] == -1 and shared_result[1] == -1:
                print("Minimization done!")
                break

            # adjust granularity
            if not (shared_result[0] == -1 and shared_result[1] == -1): # If a crash occured, change both the payload size and the payload itself
                if not (shared_result[0] == 0 and shared_result[1] == shared_payload_size.value): # Granularity of 1 will just test the input
                    shared_payload_size.value = shared_payload_size.value - (shared_result[1] - shared_result[0])
                    complement = bytearray(create_complement_payload(payload, (shared_result[0], shared_result[1])))
                    for i, b in enumerate(complement):
                        payload[i] = b
                granularity = max(granularity - 1, 2)
            else:
                if granularity == 1: # Test input did not crash
                    print("Initial input did not crash!!!")
                    break
                granularity = min(granularity * 2, shared_payload_size.value)
            print(f"Granularity changed to {granularity}, payload size is {shared_payload_size.value}/{initial_payload_size}")
            reset_shared_state(shared_number_of_completed_jobs, shared_result)
            taken_jobs = 0
            iteration_counter += 1
    except KeyboardInterrupt:
        print("Got CTRL-C, shutting down workers...")
    finally:
        save_payload(config, payload, shared_payload_size.value)
        graceful_exit(workers, None, None)
