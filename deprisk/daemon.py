import sys
import time
from typing import Callable


def run_loop(
    tick: Callable[[], int],
    interval: float,
    iterations: int | None = None,
    sleep=time.sleep,
) -> int:
    """Run `tick` on an interval. Returns the last non-zero exit code seen."""
    last_code = 0
    count = 0
    try:
        while iterations is None or count < iterations:
            try:
                code = tick()
                if code:
                    last_code = code
            except Exception as exc:  # noqa: BLE001 - daemon must survive ticks
                print(f"drift tick failed: {exc}", file=sys.stderr)
            count += 1
            if iterations is None or count < iterations:
                sleep(interval)
    except KeyboardInterrupt:
        print("daemon stopped", file=sys.stderr)
    return last_code
