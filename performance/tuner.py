from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable

from .url_cases._models import EXPECTATION_UNKNOWN


@dataclass
class TunableDataset:
    """
    A URLDataset look-alike (same `.name`/`.urls`/`.size`) whose size
    self-adjusts. `urls` regenerates from `make_urls(n)` on every access, so
    a size change made after one operation is picked up by the next.
    """

    name: str
    make_urls: Callable[[int], list[str]]
    n: int
    min_n: int = 100
    max_n: int = 20_000
    target_low_ms: float = 300.0
    target_high_ms: float = 1000.0
    shrink_factor: float = 0.8
    grow_factor: float = 1.1

    # Same per-dataset operation-control fields as URLDataset (see its
    # docstring) -- unused by any tunable dataset today, but present so
    # run_suite() can read them uniformly across both dataset types.
    excluded_operations: frozenset[str] = field(default_factory=frozenset)
    skip_repeated_parse: bool = False

    # Same idea as URLDataset.expectation -- every tunable dataset's
    # generator produces internally homogeneous output (e.g. every URL from
    # generate_invalid_port_urls() is equally invalid), so a single
    # dataset-wide value is enough; there's no per-URL override here since
    # `.urls` itself is regenerated on every access.
    expectation: str | None = None

    @property
    def urls(self) -> list[str]:
        return self.make_urls(self.n)

    @property
    def size(self) -> int:
        return self.n

    @property
    def expectations(self) -> tuple[str, ...]:
        """One expectation per URL, aligned 1:1 with `.urls` (see URLDataset)."""
        return tuple((self.expectation or EXPECTATION_UNKNOWN) for _ in range(self.size))

    def _adjustment_factor(
        self,
        distance: float,
        base_factor: float,
        max_adjustment: float | int = 2,
        min_adjustment: float | int = 0.5,
    ) -> float:
        """
        Return a multiplicative dataset-size adjustment.

        `base_factor` is the normal adjustment factor.

        The further the elapsed time is from the target boundary,
        the more aggressively the adjustment moves.

        Example:
            shrink base = 0.90
            grow base   = 1.40

        Small deviations stay close to those factors, while very large
        deviations become progressively more aggressive.
        """
        if distance <= 0:
            return 1.0

        # Normalize distance around a 10% deviation.
        normalized = distance / 0.10

        # Logarithmic aggression.
        aggression = 1.0 + 0.5 * math.log10(
            1.0 + normalized
        )

        if base_factor < 1.0:
            # Example:
            # 0.90 -> progressively smaller
            adjustment = 1.0 - (
                    (1.0 - base_factor) * aggression
            )

            return max(
                0.10,
                adjustment,
            )

        # Example:
        # 1.40 -> progressively larger
        adjustment = 1.0 + (
                (base_factor - 1.0) * aggression
        )

        return float(max(min_adjustment, min(adjustment, max_adjustment)))

    def adjust(self, elapsed_seconds: float) -> bool:
        elapsed_ms = elapsed_seconds * 1000.0
        old_n = self.n

        if elapsed_ms > self.target_high_ms:
            # Too slow -> shrink.
            distance = (
                               elapsed_ms - self.target_high_ms
                       ) / self.target_high_ms

            factor = self._adjustment_factor(
                distance,
                self.shrink_factor,
            )

            self.n = min(
                self.max_n,
                max(self.min_n, int(self.n * factor)),
            )

        elif elapsed_ms < self.target_low_ms:
            # Too fast -> grow.
            distance = (
                               self.target_low_ms - elapsed_ms
                       ) / self.target_low_ms

            factor = self._adjustment_factor(
                distance,
                self.grow_factor,
            )

            self.n = max(
                self.min_n,
                min(self.max_n, int(self.n * factor)),
            )

        return self.n != old_n
