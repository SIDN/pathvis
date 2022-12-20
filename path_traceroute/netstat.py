#!/usr/bin/env python3

import functools
import logging
import platform
import subprocess # nosec B404
import time
from typing import Callable, Union, Any

import psutil

from path_traceroute.util import is_valid_ip_address

logging.basicConfig(
    format="%(asctime)s %(name)s: %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger('path_traceroute.netstat')
logger.setLevel(logging.DEBUG)

IGNORE_PREFIXES = ('fe80:', '::ffff')
IGNORE_HOSTS = ('127.0.0.1', '::1')


class ConnectionListException(Exception):
    pass


# TODO: we currently reuse some data structure with a different type, depending on
# whether we are still building the structure, and whether ports are requested.
# Refactor into a data structure class.
PortsDictSet = dict[str, set[str]]
PortsDictTuple = dict[str, tuple]


def _netstat_connections(ipv4_only: bool = False, port_delim: str = '.',
                         int_delim: str = '%') -> PortsDictTuple:
    """Gathers ESTABLISHED connections using netstat and returns list of remote hosts"""
    netstat_cmd = "netstat -nalW  | grep ESTABLISHED | tr -s ' ' | cut -d ' ' -f 5"
    p = subprocess.run(netstat_cmd, shell=True, stdout=subprocess.PIPE) # nosec B602
    ports_by_destination: PortsDictSet = {}
    for line in p.stdout.decode().splitlines():
        destination, port = line.rsplit(port_delim, 1)
        destination, *_interface = destination.split(int_delim, 1)
        ports_by_destination.setdefault(destination, set()).add(port)
    if ipv4_only:
        ports_by_destination = {k: v for k, v in ports_by_destination.items() if ':' not in k}

    # Modify the result data structure into either a dict of tuples, or a value tuple
    ports_by_destination_t: PortsDictTuple = {k: tuple(v) for k, v in ports_by_destination.items()}
    return ports_by_destination_t


def netstat_connections(*args: Any, **kwargs: Any) -> PortsDictTuple:
    handlers = {
        'Linux': functools.partial(_netstat_connections, port_delim=':'),
        'Darwin': _netstat_connections
    }

    handler: Any = handlers.get(platform.system())
    if not handler:
        handler = _netstat_connections
    return handler(*args, **kwargs)


def current_connections(ipv4_only: bool = False) -> PortsDictTuple:
    """Gathers ESTABLISHED connections using psutil and returns list of remote hosts"""
    psutil_result = set()
    try:
        kind = 'inet'
        if ipv4_only:
            kind = 'inet4'
        for connection in (psutil.net_connections(kind=kind)):
            addr, status = connection[4:6]
            if addr and status in ['ESTABLISHED']:
                psutil_result.add(addr)
    except (psutil.AccessDenied, RuntimeError):
        raise ConnectionListException
    ports_by_destination: PortsDictSet = {}
    for destination in psutil_result:
        ports_by_destination.setdefault(destination.ip, set()).add(str(destination.port))
    ports_by_destination_t = {k: tuple(v) for k, v in ports_by_destination.items()}
    return ports_by_destination_t


def active_remote_hosts(ipv4_only: bool = False) -> PortsDictTuple:
    """Gathers a list of remote hosts using various methods and filters the output"""
    try:
        remote_hosts = current_connections(ipv4_only)
    except ConnectionListException:
        # try the hacky way
        remote_hosts = netstat_connections(ipv4_only)
    remote_hosts = {k: v for k, v in remote_hosts.items() if
                    k not in IGNORE_HOSTS and not k.startswith(IGNORE_PREFIXES)}
    version = None
    if ipv4_only:
        version = 4
    try:
        assert all(
            [is_valid_ip_address(ip, version=version) for ip in remote_hosts]), 'remote_hosts contain non-ip values'
    except AssertionError as e:
        logger.error('Remote hosts contains non-ip values: %s', remote_hosts)
        raise e
    return remote_hosts


def mock_active_remote_hosts(remote_hosts: list[list[str]], interval: int = 20) -> Callable:
    """Mocks a list of remote hosts"""
    options = remote_hosts
    last = time.time()
    value = options[0]

    def mocked_active_remote_hosts(ipv4_only: bool = False) -> PortsDictTuple:
        nonlocal options, value, last
        ports_by_destination: PortsDictSet = {}
        if time.time() > last + interval:
            last = time.time()
            if options.index(value) == len(options) - 1:
                value = options[0]
            else:
                value = options[options.index(value) + 1]
        for item in value:
            addr, *ports = item.split('_')
            if not ports:
                port = '0'
            else:
                port = ports[0]
            ports_by_destination.setdefault(addr, set()).add(port)
        version = None

        ports_by_destination_t: PortsDictTuple = {k: tuple(v) for k, v in ports_by_destination.items()}

        value_filtered = tuple(ports_by_destination_t.keys())
        if ipv4_only:
            value_filtered = tuple(filter(lambda v: is_valid_ip_address(v, version=4), value))
            version = 4
        assert all([is_valid_ip_address(ip, version=version) for ip in
                    value_filtered]), 'mocked_remote_hosts contain non-ip values'

        return ports_by_destination_t

    return mocked_active_remote_hosts


if __name__ == '__main__':
    """Run the main function asynchronously"""
    g_ipv4_only = False
    active_hosts_func = mock_active_remote_hosts([['8.8.8.8', '10.0.0.1_443'], ['10.0.0.2', '10.0.0.3_443']],
                                                 interval=1)

    mocked_remote_hosts = active_hosts_func(ipv4_only=g_ipv4_only)

    active_hosts_func = active_remote_hosts
    active_hosts = active_hosts_func(ipv4_only=g_ipv4_only)

    print('mocked: ', mocked_remote_hosts)
    print('active: ', active_hosts)
