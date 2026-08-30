import logging

from kafl_fuzzer.minimizer.variants import minimize_simple, minimize_fast, minimize_extreme

log = logging.getLogger(__name__)

MINIMIZER_VARIANTS = {
    "simple": minimize_simple,
    "fast": minimize_fast,
    "extreme": minimize_extreme
}


def start(config):
    variant = getattr(config, "minimizer_variant", "simple")
    minimizer = MINIMIZER_VARIANTS.get(variant)
    if minimizer is None:
        log.error("Unknown minimizer variant: %s", variant)
        return -1
    return minimizer(config)
