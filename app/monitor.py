import asyncio
import time

from const import (
    BUSY_WEIGHT,
    COOLDOWN_SECONDS,
    COOLDOWN_THRESHOLD,
    EMA_ALPHA,
    FAILURE_WEIGHT,
)
from mylogging import mylogging
from pydantic import BaseModel

logger = mylogging.getLogger("monitor")


class Stat(BaseModel):
    host: str  # ClamAV hostname
    port: int  # ClamAV port
    busy: int = 0  # number of concurrent scans in progress
    avg_time: float = 0.0  # avg scan time in seconds (EMA)
    count: int = 0  # number of completed scans used in avg
    failures: int = 0  # consecutive failures
    last_failure: float = 0.0  # timestamp of last failure


class Monitor:
    def __init__(self, clamd_hosts: list[tuple[str, int]]):
        """Initialize."""
        self.clamd_hosts = clamd_hosts
        self._statistics = {}
        self._host_stats = {}
        self._stats_lock = asyncio.Lock()
        self._next_clamd_index = 0

        self.load()

    @property
    def statistics(self):
        """Return statistics."""
        return self._statistics

    def load(self):
        """Load stats."""
        if self.clamd_hosts:
            for host, port in self.clamd_hosts:
                key = self.host_key(host, port)
                if key not in self._host_stats:
                    self._host_stats[key] = Stat(host=host, port=int(port))
                    logger.info("load: " + str(self._host_stats[key]))

    def host_key(self, host: str, port: int) -> str:
        """Generate host key string."""
        return f"{host}:{port}"

    async def mark_host_busy(self, key: str):
        """Set busy."""
        async with self._stats_lock:
            self._host_stats[key].busy += 1

    async def mark_host_done(
        self, key: str, success: bool, elapsed: float | None = None
    ) -> None:
        """
        Decrement busy, update avg_time (EMA) if elapsed provided, and update failure counters.
        """
        async with self._stats_lock:
            s = self._host_stats[key]
            # busy decrement, never below 0
            s.busy = max(0, s.busy - 1)

            now = time.time()
            if success:
                s.failures = 0
                s.last_failure = 0.0
            else:
                s.failures = s.failures + 1
                s.last_failure = now

            # update avg_time only on success and if elapsed provided
            if success and elapsed is not None:
                prev = s.avg_time or 0.0
                if prev == 0.0:
                    s.avg_time = elapsed
                    s.count = 1
                else:
                    # exponential moving average
                    s.avg_time = EMA_ALPHA * elapsed + (1 - EMA_ALPHA) * prev
                    s.count = s.count + 1

            self._host_stats[key] = s

            logger.debug("Stats %s", self._host_stats)
            logger.debug("Mark host %s %s %s", key, success, elapsed)

    async def select_best_host(self) -> tuple[str, int, str]:
        """
        Select best host according to hybrid score.
        Hosts in cooldown get penalty, but if all are in cooldown fallback to round-robin.
        """
        async with self._stats_lock:
            self.load()

            best_key = None
            best_score = float("inf")
            now = time.time()

            for key, s in self._host_stats.items():
                # cooldown penalty
                cooldown_active = (
                    s.failures >= COOLDOWN_THRESHOLD
                    and (now - s.last_failure) < COOLDOWN_SECONDS
                )
                penalty = 1e9 if cooldown_active else 0.0

                score = (
                    s.busy * BUSY_WEIGHT
                    + s.avg_time
                    + s.failures * FAILURE_WEIGHT
                    + penalty
                )

                if score < best_score:
                    best_score = score
                    best_key = key

            if best_key is None and self.clamd_hosts:
                host, port = self.clamd_hosts[
                    self._next_clamd_index % len(self.clamd_hosts)
                ]
                key = self.host_key(host, port)
                self._next_clamd_index = (self._next_clamd_index + 1) % len(
                    self.clamd_hosts
                )
                logger.debug("Best host: %s %s %s", host, port, key)
                await self.update_monitor_state()
                return host, port, key

            logger.debug("Best host: %s %s %s", s.host, s.port, best_key)  # type: ignore
            await self.update_monitor_state()
            return s.host, s.port, best_key  # type: ignore

    async def reset_host_failures_periodically(self) -> None:
        """
        Periodically reset failures of hosts whose cooldown has expired.
        Ensures that rebooted ClamAV instances become selectable again.
        """
        while True:
            async with self._stats_lock:
                now = time.time()
                for s in self._host_stats.values():
                    if (
                        s.failures >= COOLDOWN_THRESHOLD
                        and (now - s.last_failure) > COOLDOWN_SECONDS
                    ):
                        logger.info(
                            f"[monitor] Reseting host {s.host}:{s.port} failures after cooldown"
                        )
                        s.failures = 0
                        s.last_failure = 0.0
            await asyncio.sleep(COOLDOWN_SECONDS / 2)

    async def update_monitor_state(self):
        state = {"timestamp": time.time()}
        for key, stats in self._host_stats.items():
            state.update({key: stats.model_dump()})
        self._statistics = state
