#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections import deque, namedtuple
from concurrent.futures import ThreadPoolExecutor

import mtrpacket # type: ignore
import websockets

from .traceroute import get_traceroute, TracerouteError
from ..util import get_local_ip, get_utc_time

from typing import TYPE_CHECKING, Optional, Any
if TYPE_CHECKING:
    from asyncio import Task
    from .traceroute import Traceroute

TRACE_INTERVAL = 5

logging.basicConfig(
    format="%(asctime)s %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger('path_traceroute.tracer')

Trace = namedtuple('Trace', ['start', 'destination', 'change', 'duration', 'trace', 'traceback', 'dports', 'cnames'])


class Tracer:
    """Tracks (and performs) a trace to a certain IP"""

    def __init__(self, destination: str, only_changes: bool = True, proto: Optional[str] = None) -> None:
        self.local_host = get_local_ip()
        self.destination = destination
        if destination == "":
            raise ValueError('Got empty destination')
        self.only_changes = only_changes
        self.history: list[Trace] = []
        self.proto = proto
        self.running = False
        self.dports = None
        self.cnames: list[str] = []
        self._task: Optional[Task] = None

    def __str__(self) -> str:
        return 'trace:self.destination'

    def start(self, trace_interval: int = TRACE_INTERVAL) -> None:
        self._task = asyncio.create_task(self.astart(trace_interval))

    async def astart(self, trace_interval: int = TRACE_INTERVAL) -> None:
        """Starts a periodic trace"""
        self.running = True
        # print('starting trace:', self.local_host, '...',  self.destination)
        try:
            await self._loop(trace_interval)
        except asyncio.CancelledError:
            self._stop()
            logger.warning(f'tracer {self.destination} cancelled')
        except Exception as e:
            # We catch all exceptions here and log them immediately
            # Otherwise they will only be raised after the task completed
            # Which is when the trace is stopped or if you cancel the program ;-)
            logger.exception(e)
            raise e

    def _stop(self) -> None:
        self.running = False

    async def stop(self) -> None:
        """Stops the periodic trace"""
        self._stop()
        if self._task:
            return await self._task
        return None

    async def traceback(self) -> Any:
        """Tries top connect to the traceback service (remote.py) and returns a reverse trace"""
        return None

    async def _loop(self, trace_interval: int = TRACE_INTERVAL) -> None:
        """Main loop, does periodic tracing, bookkeeping, filtering and updates trace history"""
        last: Optional[list[Optional[str]]] = None
        dports_last: Optional[list[Optional[str]]] = None
        max_ttl = 64
        logger.info('start tracing %s', self.destination)
        while self.running and trace_interval:
            try:
                start = get_utc_time()
                tr = await self.one_trace(max_ttl=max_ttl, proto=self.proto)
                end = get_utc_time()

                if not any(tr):  # if everything in the trace is None, ignore.
                    continue

                if len(tr) == max_ttl - 1:  # probably some crap in trace, ignore.
                    continue

                if tr[-1] is None:  # trace ends on none instead of destination, ignore.
                    continue
                # Not sure why we had this code (RK) lets try without since we cant manipulate namedtuple
                # for h in self.history:
                #    if h.destination == self.destination: h.change = False

                # When length is the same update the last trace with non-null values and use that as new trace
                # packets get lost, let's not replace information with nothingness ;-)
                if last is not None and len(tr) == len(last):
                    merged_trace = []
                    for oldhop, newhop in zip(last, tr):
                        if newhop is None:
                            merged_trace.append(oldhop)
                        else:
                            merged_trace.append(newhop)
                    tr = merged_trace

                if last is None or dports_last is None:
                    change = True
                else:
                    change = not (tr == last and dports_last == self.dports)

                if change:
                    logging.debug('change for: %s ... %s', self.local_host, self.destination)
                    logging.warning('old> %s %s', last, dports_last)
                    logging.warning('new> %s %s', tr, self.dports)
                    last = tr

                dports_last = self.dports

                if not self.only_changes or change:
                    traceback = await self.traceback()
                    trace = Trace(start, self.destination, change, end - start, tr, traceback, self.dports, 2)
                    self.history.append(trace)
            finally:
                if self.running:
                    await asyncio.sleep(trace_interval)
        # Since we are not running, add a last empty trace
        logger.info('stopped tracing %s', self.destination)
        self.history.append(Trace(get_utc_time(), self.destination, True, 0, [], [], [], self.cnames))

    async def one_trace(self, probe_timeout: int = 3, max_ttl: int = 256, proto: Optional[str] = None) -> list[Optional[str]]:
        """Just do one trace to the remote endpoint and return the result"""
        if proto is None:
            proto = "icmp"
        trace = []
        async with mtrpacket.MtrPacket() as mtr:
            for ttl in range(1, max_ttl):
                result = await mtr.probe(self.destination, ttl=ttl, local_ip=self.local_host, timeout=probe_timeout,
                                         protocol=proto)
                if result.responder:
                    trace.append(result.responder)
                else:
                    trace.append(None)
                if result.success:
                    break
        return trace


class TracerouteTracer(Tracer):
    cycle_protocols = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.traceroute_executor = ThreadPoolExecutor(max_workers=1)
        self.traceroute: Optional[Traceroute] = None
        self.failcount = 0
        self.backoff_until: Optional[float] = None

    def _stop(self) -> None:
        if self.traceroute:
            self.traceroute.kill()  # and let's be aggressive about it ;-)
        self.traceroute_executor.shutdown()  # stop doing the thing!!
        super()._stop()

    def cycle_protocol(self, traceroute: Traceroute, pref: Optional[list[str]] = None) -> str:
        if pref is None:
            pref = ['icmp', 'udp', 'tcp']
        if not isinstance(self.cycle_protocols, deque):
            capabilities = traceroute.capabilities_for_host(self.destination)
            cap_by_pref = [proto for proto in pref if proto in capabilities] + list(capabilities)
            self.cycle_protocols = deque(cap_by_pref)
        proto = self.cycle_protocols.popleft()
        self.cycle_protocols.append(proto)
        return proto

    async def one_trace(self, probe_timeout: int = 3, max_ttl: int = 64, proto: Optional[str] = None) -> list[Optional[str]]:
        """Just do one trace to the remote endpoint and return the result"""
        if self.backoff_until is not None:
            if time.time() < self.backoff_until:
                logger.info('trace to %s failed %sx backoff, next attempt in %ss', self.destination, self.failcount,
                            (self.backoff_until - time.time()))
                return []
        self.traceroute = traceroute = get_traceroute(giveup=5, probe_timeout=probe_timeout, max_hops=max_ttl)
        traceroute.probe_timeout = probe_timeout
        traceroute.max_hops = max_ttl

        if proto is None:
            proto = self.cycle_protocol(traceroute)
            logger.info('cycling protocol for %s to %s', self.destination, proto)
        loop = asyncio.get_running_loop()
        traceroute_call = functools.partial(traceroute.trace, self.destination, proto=proto)
        try:
            traceroute_thread = loop.run_in_executor(self.traceroute_executor, traceroute_call)
            start = time.clock_gettime(time.CLOCK_MONOTONIC)
            result = await traceroute_thread
            end = time.clock_gettime(time.CLOCK_MONOTONIC)
            logger.info('traceroute to %s using %s took %.2fs', self.destination, proto, (0.0 + end - start))
        except TracerouteError as e:
            logger.exception(e)
            result = []

        if self.destination not in result:
            # partial traceroute it probably gave up
            self.failcount = self.failcount + 1
            if self.failcount > 1:
                self.backoff_until = time.time() + (TRACE_INTERVAL * self.failcount)
        else:
            self.failcount = 0
            self.backoff_until = None
        return result


async def main() -> None:
    """Run the main loop and the websocket server (forever)"""
    tracemethod = TracerouteTracer
    addr = '35.190.27.69'
    tracer = tracemethod(addr, only_changes=True)
    asyncio.create_task(tracer.astart(TRACE_INTERVAL))


if __name__ == '__main__':
    """Run the main function asynchronously"""
    asyncio.run(main())
