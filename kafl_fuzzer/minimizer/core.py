import logging
import multiprocessing
from multiprocessing.sharedctypes import Synchronized
import os
import signal
import sys
import time
import queue

from kafl_fuzzer.common.util import read_binary_file
from kafl_fuzzer.worker.qemu import qemu
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.common.logger import WorkerLogAdapter

log = logging.getLogger(__name__)

JOB_SUBSET      = 0
JOB_COMPLEMENT  = 1

class FastWorker(multiprocessing.Process):
    def __init__(
            self,
            worker_id: int,
            qemu_config,
            input_queue: multiprocessing.Queue,
            payload,
            payload_size,
            result,
            condition_lock,
            number_of_completed_jobs,
            metric_execution_count: Synchronized
    ):
        multiprocessing.Process.__init__(self, target=self.target)
        self.worker_id = worker_id
        self.qemu_config = qemu_config
        self.qemu_instance = None
        self.logger_no_prefix = logging.getLogger(__name__)
        self.log = WorkerLogAdapter(self.logger_no_prefix, {'pid': self.worker_id})
        # shared variables
        self.input_queue: multiprocessing.Queue[tuple[int, int]] = input_queue
        self.payload = payload
        self.payload_size = payload_size
        self.result = result
        self.condition_lock = condition_lock
        self.number_of_completed_jobs = number_of_completed_jobs

        # Metrics
        self._metric_execution_count = metric_execution_count
        if self._metric_execution_count:
            self._metric_exists = True

    def target(self):
        try:
            signal.signal(signal.SIGTERM, self.sigterm_handler)
            self.log.info(f"Initializing worker {self.worker_id}")
            self.worker_loop()
            self.shutdown_worker()
        except KeyboardInterrupt:
            self.shutdown_worker()

    def worker_loop(self):
        if self.init_qemu() is False:
            return
        try:
            while True:
                job = self.get_job()
                if job is None: # Queue is empty which means that the iteration ended and the queue will be populated soon
                    continue
                self.handle_job(job)
        except:
            self.shutdown_worker()

    def is_result_exist(self):
        return self.result[0] != -1 and self.result[1] != -1

    def get_job(self):
        try:
            return self.input_queue.get(timeout=0.1)
        except queue.Empty:
            return None

    def handle_job(self, job):
        payload = None

        with self.condition_lock:
            if self.is_result_exist():
                self.number_of_completed_jobs.value += 1
                self.condition_lock.notify()
                return
            if job[2] == JOB_SUBSET:
                payload = bytearray(create_subset_payload(self.payload, (job[0], job[1])))
            elif job[2] == JOB_COMPLEMENT:
                payload = bytearray(create_complement_payload(self.payload, (job[0], job[1]), self.payload_size.value))
            else:
                log.error("Unknown job type")
                self.number_of_completed_jobs.value += 1
                self.condition_lock.notify()
                return

        is_crash = None

        if self._metric_exists:
            is_crash, _ = test_payload_with_metrics(self.qemu_instance, payload, self._metric_execution_count)
        else:
            is_crash, _ = test_payload(self.qemu_instance, payload)

        with self.condition_lock:
            self.number_of_completed_jobs.value += 1
            if is_crash and not self.is_result_exist():
                self.log.debug(f"Worker {self.worker_id}: CRASH FOUND in {'subset' if job[2] == JOB_SUBSET else 'complement'}, offset: ({job[0]},{job[1]})")
                self.result[0] = job[0]
                self.result[1] = job[1]
            self.condition_lock.notify()

    def init_qemu(self):
        self.qemu_instance = qemu(
            self.worker_id,
            self.qemu_config,
            debug_mode=False,
            resume=self.qemu_config.resume,
        )

        if not self.qemu_instance.start():
            self.log.error("Failed to start Qemu")
            return False

        return True

    def shutdown_worker(self):
        self.log.info("Shutting down worker")
        self.sigterm_handler()

    def sigterm_handler(self, signal=None, frame=None):
        if self.qemu_instance:
            self.log.info(f"Worker {self.worker_id}: SIGTERM")
            self.qemu_instance.async_exit()
            sys.exit(0)
        else:
            sys.exit(0)


def graceful_exit(workers=[], signal=None, frame=None):
    print("Exiting")
    for s in reversed(workers):
        time.sleep(0.5)
        s.terminate()

    while len(workers) > 0:
        for s in reversed(workers):
            if s and s.exitcode is None:
                print(
                    "Still waiting on %s (pid=%d)..  [hit Ctrl-c to abort..]"
                    % (s.name, s.pid)
                )
                s.join(timeout=5)
            else:
                workers.remove(s)
    return 0

def test_payload(q, payload: bytearray) -> tuple[bool, ExecutionResult]:
    q.set_payload(payload)
    result = q.send_payload()
    if result.is_crash() and result.exit_reason == "crash":
        return (True, result)
    return (False, None)

def test_payload_with_metrics(q, payload: bytearray, metric: Synchronized) -> tuple[bool, ExecutionResult]:
    with metric.get_lock():
        metric.value += 1

    q.set_payload(payload)
    result = q.send_payload()
    if result.is_crash() and result.exit_reason == "crash":
        return (True, result)
    return (False, None)


def load_payload(config):
    payload_file = config.input
    payload_limit = config.payload_size - qemu.payload_header_size

    assert os.path.isfile(payload_file), "Provided --input argument must be a file."
    assert payload_limit >= 0, "Payload limit is negative, must be at least 4"

    payload = read_binary_file(payload_file)

    if len(payload) > payload_limit:
        log.info(f"Payload is bigger than configured ({len(payload)} > {payload_limit}), trimming payload")
        payload = payload[:payload_limit]

    return payload

def reset_shared_state(shared_number_of_completed_jobs, shared_result):
    with shared_number_of_completed_jobs.get_lock():
        shared_number_of_completed_jobs.value = 0
    with shared_result.get_lock():
        shared_result[0] = -1
        shared_result[1] = -1

def create_chunk_offsets(payload_len, granularity) -> list[tuple[int, int]]:
    """ Create list of offsets from given payload length and granularity """
    return [(i*payload_len//granularity, (i+1)*payload_len//granularity) for i in range(granularity)]

def create_sliding_window_offsets(payload_len, window_size) -> list[tuple[int, int]]:
    """ Create list of offsets iterated by 1 byte """
    result = []
    i = 0

    if window_size < 1:
        return result

    while i + window_size <= payload_len:
        result.append((i, i + window_size))
        i += 1
    return result


def save_payload(config, payload, payload_size):
    with open(config.workdir + "/minimized_payload", "wb") as fh:
        res_payload = bytearray(payload[0:payload_size])
        fh.write(res_payload)

def create_complement_payload(payload, offset: tuple[int, int], size=None) -> bytes:
    if size is None:
        size = len(payload)
    return payload[0:offset[0]] + payload[offset[1]:size]

def create_subset_payload(payload, offset: tuple[int, int]) -> bytes:
    return payload[offset[0]:offset[1]]
