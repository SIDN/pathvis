#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import logging
import time
import websockets

from itertools import chain

from .node_info import hop_info
from .tracer import Trace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from path_traceroute.tracer import TracerouteTracer
    import websockets.server

WS_PUBLISH_INTERVAL = 1

logging.basicConfig(
    format="%(asctime)s %(name)s: %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger('path_traceroute.websocket_server')

class WebsocketServer:
    def __init__(self):
        self.running = True
        self.active_tracers: list[TracerouteTracer] = []
        self.removed_tracers: list[TracerouteTracer] = []

    def update_tracers(self, active: list[TracerouteTracer], removed: list[TracerouteTracer]) -> None:
        self.active_tracers = active
        self.removed_tracers = removed

    def get_handler(self):
        async def websocket_handler(websocket: websockets.server.WebSocketServerProtocol, _path: str) -> None:
            '''This handles websockets, specifically it sends traces to a websockets
               To avoid repeating duplicate traces we do some additional bookkeeping here
            '''
            processed_traces_by_destination: dict[str, list[tuple[str, str]]] = {}

            def all_processed_traces() -> list[tuple[str, str]]:
                '''gets all the traces from processed_traces_by_destination'''
                nonlocal processed_traces_by_destination
                return list(chain.from_iterable(processed_traces_by_destination.values()))

            async def send_trace(trace: Trace, new: bool=False) -> None:
                '''enriches trace a single trace and send over a websocket'''
                as_path = await asyncio.gather(*[hop_info(hop) for hop in trace.trace])
                o = {
                        'start': trace.start,
                        'destination': trace.destination,
                        'change': trace.change,
                        'duration': trace.duration,
                        'trace': list(enumerate(as_path)),
                        'dports' : trace.dports,
                        'cnames' : trace.cnames,
                        'new': new
                    }
                await websocket.send(json.dumps(o, indent=2, sort_keys=True))

            async def send_clear_cache() -> None:
                await websocket.send('clear_cache')
                logging.debug('new connection, sending clear_cache')

            async def send_traces() -> None:
                '''Sends active traces that have not been sent yet, or when they changed or if they are removed'''
                nonlocal processed_traces_by_destination
                active_destinations = [t.destination for t in self.active_tracers]
                logger.info('active_tracers: %s ', sorted(active_destinations))
                removed_destinations = [t.destination for t in self.removed_tracers]
                logger.info('removed_tracers: %s ', sorted(removed_destinations))
                as_path = None
                all_active_traces: list[Trace] = sum([tracer.history for tracer in self.active_tracers], [])
                for trace_entry in all_active_traces:
                    start, host, *_rest = trace_entry
                    trace_key = (trace_entry.start, trace_entry.destination)
                    if trace_key in all_processed_traces():
                        logger.info('trace already processed')
                        continue
                    logger.info('publish trace %s (started=%s)', host, start)
                    processed_traces_by_destination.setdefault(host, []).append(trace_key)
                    await send_trace(trace_entry, new=True)
                # remove inactive traces
                for tracer in self.removed_tracers:
                    if tracer.destination in processed_traces_by_destination.keys():
                        await send_trace(tracer.history[-1], new=False)
                        logger.info('removing destination %s from processed traces', tracer.destination)
                        del processed_traces_by_destination[tracer.destination]
                logger.info('traces: %s destinations: %s', len(list(all_processed_traces())), len(processed_traces_by_destination.keys()))
                logger.info('processed_traces_by_destination: %s', list(processed_traces_by_destination.keys()))
                return as_path

            await send_clear_cache()
            while self.running:
                await send_traces()
                await asyncio.sleep(WS_PUBLISH_INTERVAL)

        return websocket_handler


async def main() -> None:
    '''Run the main loop and the websocket server (forever)'''
    async with websockets.serve(websocket_handler, "localhost", 8765):  # type: ignore
        await asyncio.Future()

if __name__ == '__main__':
    '''Run the main function asynchronously'''
    asyncio.run(main())
