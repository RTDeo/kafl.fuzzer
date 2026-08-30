import logging

from kafl_fuzzer.worker.qemu import qemu
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.minimizer.core import load_payload, create_chunk_offsets, create_complement_payload, create_subset_payload, save_payload

log = logging.getLogger(__name__)


def test_payload(q, payload: bytearray, offsets: tuple[int, int]) -> tuple[bool, ExecutionResult]:
    q.set_payload(payload)
    result = q.send_payload()
    if result.is_crash():
        return (True, result)
    return (False, None)

def minimize(config):
    """Single-process complement-deletion minimizer."""
    log.info("Starting simple minimizer (single process)")

    payload = bytearray(load_payload(config))

    q = qemu(1337, config, debug_mode=False, notifiers=True, resume=config.resume)

    if not q.start():
        log.error("Failed to start Qemu")
        return -1

    granularity = 1
    iteration_counter = 1
    initial_payload_size = len(payload)
    
    try:
        # First, test the payload if it crashes
        log.info("Testing payload...")
        is_crash, offset = test_payload(q, payload)
        # q.set_payload(bytearray(payload))

        while True:
            offsets = create_chunk_offsets(len(payload), granularity)

            crash_offset = None
            subset_found = False

            log.info(f"Starting iteration {iteration_counter} with {len(offsets)} jobs")

            for offset in offsets:
                if offset[0] == 0 and offset[1] == len(payload):  # granularity 1
                    complement = bytearray(payload[:])
                else:
                    complement = bytearray(create_complement_payload(payload, offset))
                
                q.set_payload(complement)
                result = q.send_payload()
                if result.is_crash():
                    crash_offset = offset
                    log.debug(f"Crash found, offset: {offset}")
                    break
                if not (offset[0] == 0 and offset[1] == len(payload)):  # also test the chunk alone
                    subset = bytearray(create_subset_payload(payload, offset))
                    q.set_payload(subset)
                    result = q.send_payload()
                    if result.is_crash():
                        subset_found = True
                        log.info(f"Subset crash found, offset: {offset}, shrinking payload")
                        break

            # done: byte-level granularity and nothing crashed
            if granularity == len(payload) and crash_offset is None and not subset_found:
                print("Minimization done!")
                break

            # adjust granularity
            if crash_offset is not None:
                if not (crash_offset[0] == 0 and crash_offset[1] == len(payload)):
                    del payload[crash_offset[0]:crash_offset[1]]
                if len(payload) <= 1:  # nothing left to reduce
                    print("Minimization done!")
                    break
                granularity = min(max(granularity - 1, 2), len(payload))
            elif subset_found:
                payload = subset
                granularity = min(2, len(payload))
            else:
                if granularity == 1:  # test input did not crash
                    print("Initial input did not crash!!!")
                    break
                granularity = min(granularity * 2, len(payload))
            print(f"Granularity changed to {granularity}, payload size is {len(payload)}/{initial_payload_size}")
            iteration_counter += 1
    except KeyboardInterrupt:
        print("Got CTRL-C, aborting...")
    except Exception as e:
        log.error(f"Minimizer error: {e}")
    finally:
        save_payload(config, payload, len(payload))
        q.shutdown()
    return 0
