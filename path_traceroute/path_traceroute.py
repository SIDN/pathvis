#!/usr/bin/env python3

import argparse
import asyncio
import logging
import logging.config
import os
import threading
import time
from collections.abc import Mapping
from typing import Callable, Optional

import dns.resolver
import websockets

from .netstat import active_remote_hosts, mock_active_remote_hosts
from .node_info import use_our_resolver as dis_use_our_resolver
from .reverse_query_lookup import lookup, reader
from .tracer import TracerouteTracer
from .util import get_local_ip

from .websocket_server import WebsocketServer

UPDATE_INTERVAL = 10
TRACE_INTERVAL = 5

logging.basicConfig(format="%(asctime)s %(name)s: %(message)s", level=logging.INFO, )

logger = logging.getLogger('traceroute')
logger.setLevel(logging.DEBUG)
logger = logging.getLogger('path_traceroute')
logger.setLevel(logging.INFO)

if os.path.exists('logging.config'):
    logging.config.fileConfig('logging.config')
    print('using config file')

tracemethod = TracerouteTracer

# tracemethod=Tracer

def start_dnsmasq_reader(logfile: str) -> None:
    t = threading.Thread(target=reader, args=[logfile], kwargs={'silent': True}, daemon=True)
    t.start()


async def main_loop(websocket_server: WebsocketServer, interval: int, active_hosts_func: Optional[Callable] = None, ipv4_only: bool = False,
                    traceproto: Optional[str] = None) -> None:
    """main applicaiton loop, runs traces for active connection and prints stuff"""
    assert active_hosts_func is not None, "no active_hosts_func supplied"

    running = True
    active_tracers: list[tracemethod] = []

    try:
        while running:
            _active_remote_hosts = active_hosts_func(ipv4_only=ipv4_only)
            logger.info('active_remote_hosts %s', sorted(_active_remote_hosts))
            active_destinations = [t.destination for t in active_tracers]
            tracer: Optional[tracemethod] = None
            for addr in _active_remote_hosts:
                if addr == get_local_ip():
                    continue
                if addr in active_destinations:
                    if isinstance(_active_remote_hosts, Mapping) and tracer is not None:
                        tracer.dports = _active_remote_hosts[addr]
                    continue
                tracer = tracemethod(addr, only_changes=True, proto=traceproto)
                tracer.cnames = lookup(addr)
                if isinstance(_active_remote_hosts, Mapping):
                    tracer.dports = _active_remote_hosts[addr]
                active_tracers.append(tracer)
                tracer.start()
                await asyncio.sleep(0.05)
            # Remove
            removed_tracers: list[tracemethod] = []
            for tracer in active_tracers:
                if tracer.destination not in _active_remote_hosts:
                    active_tracers.remove(tracer)
                    removed_tracers.append(tracer)
                    await tracer.stop()
            assert set(removed_tracers).isdisjoint(set(active_tracers)), 'removed traces still seem to be active?'
            websocket_server.update_tracers(active_tracers, removed_tracers)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        start = time.time()
        await asyncio.gather(*[tracer.stop() for tracer in active_tracers], return_exceptions=True)
        logger.info('Stopping Tracers took: %s seconds', int(time.time() - start))
    except Exception as exc:
        # We catch all exceptions here and log them immediately
        # Otherwise they will only be raised after the task completed
        # Which is when you cancel the program ;-)
        logger.exception(exc)
        raise exc


async def main() -> None:
    """Run the main loop and the websocket server (forever)"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-4', '--ipv4_only', action='store_true', help='ipv4 only')
    parser.add_argument('-M', '--mock', action='store_true', help='mock active hosts')
    parser.add_argument('-R', '--our_resolver', action='store_true',
                        help='use our own Unbound instance for DNS (which fakes some DIS TXT records)')
    parser.add_argument('-Q', '--query_log', type=str, help='dnsmasq logfile containing replies to forward lookups')
    parser.add_argument('-t', '--traceproto', type=str, default=None,
                        help='use specific protocol for traceroute e.g. icmp')
    args = parser.parse_args()
    if args.mock:
        # hosts_list = [ ['145.100.132.1'], [], ['8.8.8.8'] ]
        logging.warning('Using mocked hosts')
        hosts_list: list[list[str]] = [
            ['8.8.8.8', '35.190.27.69', '2a04:b900::1:0:0:10', '185.55.136.59', '145.18.11.145'], [],
            ['8.8.8.8']]
        active_hosts_func = mock_active_remote_hosts(hosts_list, interval=15)
    else:
        active_hosts_func = active_remote_hosts

    if args.our_resolver:
        logger.warning('Using our own Unbound instance for DNS')
        dis_use_our_resolver()

    if args.query_log:
        logger.warning(f'Tailing dnsmasq log {args.query_log} for dns queries')
        start_dnsmasq_reader(args.query_log)

    traceproto = None
    if args.traceproto:
        traceproto = args.traceproto

    loop = asyncio.get_running_loop()
    websocket_server = WebsocketServer()
    t = loop.create_task(main_loop(websocket_server, UPDATE_INTERVAL, active_hosts_func=active_hosts_func, ipv4_only=args.ipv4_only,
                                   traceproto=traceproto))
    async with websockets.serve(websocket_server.get_handler(), 'localhost', 8765):  # type: ignore
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await t
            logger.info('Main loop cancelled.')


if __name__ == '__main__':
    """Run the main function asynchronously"""
    asyncio.run(main())
