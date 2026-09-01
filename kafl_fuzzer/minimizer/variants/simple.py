import logging
import time
import multiprocessing as m
import ctypes

from kafl_fuzzer.worker.qemu import qemu
from kafl_fuzzer.minimizer.core import test_payload_with_metrics, test_payload, load_payload, create_chunk_offsets, create_complement_payload, create_subset_payload, save_payload

log = logging.getLogger(__name__)




# Original recursive ddmin, used as a reference
# def ddmin(q, payload, n) -> bytearray:
#     # Divide to chunks of n
#     offsets = create_chunk_offsets(len(payload), n)
    
#     # Test subsets
#     for offset in offsets:
#         subset = create_subset_payload(payload, offset)
#         is_crash, _ = test_payload(q, subset)
#         if is_crash is True:
#             # Reset granularity to 2
#             n = 2
#             return ddmin(q, subset, n)
    
#     for offset in offsets:
#         complement = create_complement_payload(payload, offset)
#         is_crash, _ = test_payload(q, complement)
#         if is_crash is True:
#             # Reset granularity to max(n-1, 2)
#             return ddmin(q, complement, max(n - 1, 2))
    
#     # No crash found, check if granularity is at payload size (1 byte chunks mean we have the answer)
#     if n == len(payload):
#         return payload

#     # Double granularity
#     return ddmin(q, payload, min(len(payload), 2 * n))

# Simple implementation of ddmin
def ddmin_simple(q, initial_payload, _metrics) -> bytearray:

    _iteration_counter = 0
    granularity = 2
    payload = initial_payload

    while True:
        _iteration_counter += 1
        is_crash = False
        current_granularity = granularity
        payload_size = len(payload)
        offsets = create_chunk_offsets(len(payload), granularity)
        
        log.debug(f"Iteration {_iteration_counter} with {len(offsets)} jobs. ({payload_size}/{len(initial_payload)})")

        # Test subsets
        for offset in offsets:
            subset = create_subset_payload(payload, offset)
            is_crash = None

            if _metrics:
                is_crash, _ = test_payload_with_metrics(q, subset, _metrics)
            else:
                is_crash, _ = test_payload(q, subset)

            if is_crash is True:
                granularity = 2
                log.debug(f"Crash found in subset, offset ({offset[0]},{offset[1]})")
                payload = subset
                break

        # If we hit subset, do the next iteration
        if is_crash is True:
            continue

        # Test complements
        for offset in offsets:
            complement = create_complement_payload(payload, offset)
            is_crash = None
            
            if _metrics:
                is_crash, _ = test_payload_with_metrics(q, complement, _metrics)
            else:
                is_crash, _ = test_payload(q, complement)

            if is_crash is True:
                granularity = max(granularity - 1, 2)
                log.debug(f"Crash found in complement, offset ({offset[0]},{offset[1]})")
                payload = complement
                break
        
        if is_crash is False:
            if current_granularity == payload_size:
                break
            # Double the granularity
            granularity = min(len(payload), 2 * granularity)
    
    return payload

def minimize(config):
    log.info("Starting simple minimizer")
    
    payload = bytearray(load_payload(config))
    
    q = qemu(1337, config, debug_mode=False, notifiers=True, resume=config.resume)

    metrics_time = None
    metrics_exec = None

    if not q.start():
        log.error("Failed to start Qemu")
        return -1

    try:
        # Before starting, test if payload even crashes
        log.info("Testing the payload first...")
        is_crash, _ = test_payload(q, payload)
        
        if is_crash is False:
            log.error("The payload did not crash!")
            return -1

        if config.metrics:
            metrics_time = time.perf_counter()
            metrics_exec = m.Value(ctypes.c_uint, 0)

        payload = ddmin_simple(q, payload, metrics_exec)

        log.info(f"Minimization done! File is now {len(payload)} bytes")
    
    except KeyboardInterrupt:
        print("Got CTRL-C, aborting...")
    
    except Exception as e:
        log.error(f"Minimizer error: {e}")
    
    finally:
        if config.metrics:
            metrics_time = time.perf_counter() - metrics_time
            metrics_exec_count = metrics_exec.value
            log.info(f"[METRICS] Execution time: {metrics_time}s | Execution count: {metrics_exec_count}")
        save_payload(config, payload, len(payload))
        q.shutdown()
    
    return 0
