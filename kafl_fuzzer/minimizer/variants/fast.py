import logging
import multiprocessing as m
import ctypes
import time

from kafl_fuzzer.common.util import filter_available_cpus
from kafl_fuzzer.minimizer.core import (
    FastWorker,
    graceful_exit,
    load_payload,
    create_chunk_offsets,
    create_complement_payload,
    create_subset_payload,
    save_payload,
    reset_shared_state,
    JOB_SUBSET,
    JOB_COMPLEMENT
)

log = logging.getLogger(__name__)

def print_stats(completed_jobs, all_jobs, granularity, payload_size, initial_payload_size):
    jobs = f"{completed_jobs}/{all_jobs}"
    granularity_s = f"{granularity}"
    chunk_size = f"{payload_size // granularity}"
    current_payload_size = f"{payload_size}/{initial_payload_size}"
    log.debug(f"[MAIN]: Stats: {jobs} jobs completed | Granularity: {granularity_s} | Chunk size: {chunk_size} | Current payload size: {current_payload_size}")

def wait_for_workers(condition_lock, completed_jobs, jobs):
    while True:
        with condition_lock:
            if condition_lock.wait_for(lambda: completed_jobs.value == jobs, timeout=1.0):
                return
            log.debug("Waiting for workers...")

def ddmin_fast(config, initial_payload):
    worker_count = config.processes
    # Updated by main process
    payload = m.Array(ctypes.c_ubyte, initial_payload)
    payload_size = m.Value(ctypes.c_uint, len(payload))
    job_queue: m.Queue[tuple[int, int, int]] = m.Queue() # (start, end, 0|1 (subset or complement))

    # Updated by main process and workers
    completed_jobs = m.Value(ctypes.c_uint, 0)

    # Updated by workers
    crash_result = m.Array(ctypes.c_int, [-1, -1]) # Offsets of the crash result
    condition_lock = m.Condition() # Used for locking critical sections and notifying the main process

    # Metrics
    metrics_exec = None
    metrics_time = None

    if config.metrics:
        metrics_exec = m.Value(ctypes.c_uint, -1) # We amount for the payload test


    workers: list[FastWorker] = [
        FastWorker(
            worker_id=worker_id,
            qemu_config=config,
            payload=payload,
            payload_size=payload_size,
            input_queue=job_queue,
            result=crash_result,
            condition_lock=condition_lock,
            number_of_completed_jobs=completed_jobs,
            metric_execution_count=metrics_exec
        )
        for worker_id in range(worker_count)
    ]

    # Start up the workers
    for worker in workers:
        worker.start()

    try:
        # First, check if payload works
        job_queue.put((0, len(initial_payload), JOB_SUBSET))

        while True:
            with condition_lock:
                finished = condition_lock.wait_for(lambda: (crash_result[0] != -1 and crash_result[1] != -1) or completed_jobs.value == 1, timeout=1.0)
                if not finished:
                    # print_stats(completed_jobs.value, 1, granularity, payload_size.value, len(initial_payload))
                    continue
                # Check if crash found
                if crash_result[0] != -1 and crash_result[1] != -1:
                    # Clear the queue
                    log.info("Clearing queue")
                    while not job_queue.empty():
                        job_queue.get()
                    break
                else:
                    log.error("Payload did not crash")
                    return

        reset_shared_state(completed_jobs, crash_result)

        granularity = 2
        _iteration_counter = 0

        if config.metrics:
            metrics_time = time.perf_counter()
    
        while True:
            _iteration_counter += 1
            offsets = create_chunk_offsets(payload_size.value, granularity)
            job_count = len(offsets)

            # Reset the state used by workers
            with condition_lock:
                completed_jobs.value = 0
                crash_result[0] = -1
                crash_result[1] = -1

            log.debug(f"Iteration {_iteration_counter} with {job_count} jobs across {len(workers)} workers. ({payload_size.value}/{len(initial_payload)})")

            # Populate queue with subset jobs
            for offset in offsets:
                job_queue.put((offset[0], offset[1], JOB_SUBSET))

            while True:
                with condition_lock:
                    finished = condition_lock.wait_for(lambda: (crash_result[0] != -1 and crash_result[1] != -1) or completed_jobs.value == job_count, timeout=1.0)
                    if not finished:
                        print_stats(completed_jobs.value, job_count, granularity, payload_size.value, len(initial_payload))
                        continue
                    # Check if crash found
                    if crash_result[0] != -1 and crash_result[1] != -1:
                        # Reset granularity to 2
                        granularity = 2
                        new_payload = bytearray(create_subset_payload(payload, (crash_result[0], crash_result[1])))
                        payload[:len(new_payload)] = new_payload
                        payload_size.value = len(new_payload)
                        break
                    if completed_jobs.value == job_count:
                        log.debug("Nothing found")
                        break

            wait_for_workers(condition_lock, completed_jobs, job_count)
            
            if crash_result[0] != -1 and crash_result[1] != -1:
                continue
            
            reset_shared_state(completed_jobs, crash_result)

            log.debug("Populating COMPLEMENT jobs...")

            for offset in offsets:
                job_queue.put((offset[0], offset[1], JOB_COMPLEMENT))

            while True:
                with condition_lock:
                    finished = condition_lock.wait_for(lambda: (crash_result[0] != -1 and crash_result[1] != -1) or completed_jobs.value == job_count, timeout=1.0)
                    if not finished:
                        print_stats(completed_jobs.value, job_count, granularity, payload_size.value, len(initial_payload))
                        continue
                    # Check if crash found
                    if crash_result[0] != -1 and crash_result[1] != -1:
                        # Reset granularity to min(n - 1, 2)
                        granularity = max(granularity - 1, 2)
                        new_payload = bytearray(create_complement_payload(payload, (crash_result[0], crash_result[1]), payload_size.value))

                        payload[:len(new_payload)] = new_payload
                        payload_size.value = len(new_payload)
                        break
                    if completed_jobs.value == job_count:
                        log.debug("Nothing found")
                        break

            wait_for_workers(condition_lock, completed_jobs, job_count)

            if crash_result[0] != -1 and crash_result[1] != -1:
                continue

            if granularity == payload_size.value:
                log.info(f"Minimization done! File is now {payload_size.value} bytes")
                break

            # Double the granularity
            granularity = min(payload_size.value, granularity * 2)
                        

    except KeyboardInterrupt:
        print("Got CTRL-C, aborting...")
        return 0
    except Exception as e:
        log.error(f"Minimizer error: {e}")
        return -1
    finally:
        if config.metrics:
            metrics_time = time.perf_counter() - metrics_time
            metrics_exec_count = metrics_exec.value
            log.info(f"[METRICS] Execution time: {metrics_time}s | Execution count: {metrics_exec_count}")
        save_payload(config, payload, payload_size.value)
        graceful_exit(workers, None, None)


def minimize(config):
    log.info("Starting fast minimizer")

    payload = bytearray(load_payload(config))

    avail, _ = filter_available_cpus()
    assert config.processes <= len(avail), "Not enough vCPUs available"
    
    return ddmin_fast(config, payload)