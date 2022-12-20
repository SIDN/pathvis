#!/usr/bin/env python3
#
# Wrapper for traceroute on various systems for path traceroute.

import ipaddress
import logging
import os
import platform
import shutil
import subprocess # nosec B404
from trace import Trace

from typing import Optional, IO, Any, Type

logger = logging.getLogger('traceroute')


class TracerouteError(Exception):
    pass


def is_ipv6(host: str) -> bool:
    """Check if an IP is ipv6"""
    try:
        _addr = ipaddress.IPv6Address(host)
    except ValueError:
        return False
    return True


def _is_privileged() -> bool:
    logger.debug('Checking whether we have sufficient privileges to raw_sockets')
    privileged = False
    if platform.system() == 'Windows':
        return False
    try:
        privileged = os.geteuid() == 0
        if privileged:
            logger.debug('We are running as root, hack the planet!')
    except AttributeError:
        # platform does not support geteuid
        pass
    if privileged or platform.system() != 'Linux':
        return privileged
    try:
        tr_location = os.path.realpath(shutil.which('traceroute') or 'POIUYTREWQWSDFGHJK')
        cmd = ['/sbin/getcap', '-r', tr_location]
    except Exception as e:
        logger.debug('Could locate traceroute binary.')
        logger.exception(e)
        return privileged

    try:
        getcap = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, # nosec B603
                                  text=True, bufsize=1)
        if getcap.stdout is not None:
            for line in getcap.stdout.readlines():
                if 'cap_net_raw=ep' in line:
                    logger.debug('Traceroute capabilities: (%s) includes "cap_net_raw" -> privileged=True', line.strip())
                    return True
                else:
                    logger.debug('We do not have raw_socket capabilities :(')
    except Exception as e:
        logger.debug('Could not figure out capabilities of %s using getcap', tr_location)
        logger.exception(e)
    return privileged


# Capabilities will likely never change during the execution.
# We figure it out once and set it to a variable.
IS_PRIVILEGED = _is_privileged()


class Traceroute:
    _nonroot_capabilities = {'icmp', 'udp', 'tcp', 'gre'}
    _root_capabilities = {'icmp', 'udp', 'tcp', 'gre'}
    _ipv6_capabilities = {'icmp', 'udp'}

    def __init__(self, probe_timeout: int = 3, max_hops: int = 64, giveup: int = 5, pref: Optional[list[str]] = None) -> None:
        if pref is None:
            pref = ['icmp', 'udp', 'tcp']
        self.giveup = giveup
        self.max_hops = max_hops
        self.pref = pref
        self.probe_timeout = probe_timeout
        self.troute: Optional[subprocess.Popen[str]] = None

    def _get_best(self, ipv6: bool = False) -> str:
        capabilities = self.capabilities(ipv6=ipv6, privileged=IS_PRIVILEGED)
        cap_by_pref = [proto for proto in self.pref if proto in capabilities] + list(capabilities)
        proto = cap_by_pref[0]
        logger.debug('Selecting supported protocol type by order of preference ->  %s', proto)
        return proto

    def _ipv6_cmd(self, host: str, proto: str ='icmp') -> list[str]:
        cmd = ["traceroute6", "-n", "-q1"]
        if proto == 'icmp':
            cmd.append('-I')
        elif proto != 'udp':
            logger.warning('protocol %s not supported for IPv6, defaulting to UDP', proto)
        if self.probe_timeout:
            cmd.extend(['-w', str(self.probe_timeout)])
        if self.max_hops:
            cmd.extend(['-m', str(self.max_hops)])
        cmd.append(host)
        return cmd

    def _ipv4_cmd(self, host: str, proto: str = 'icmp') -> list[str]:
        cmd = ["traceroute", "-n", "-q1", "-P", proto]
        if self.probe_timeout:
            cmd.extend(['-w', str(self.probe_timeout)])
        if self.max_hops:
            cmd.extend(['-m', str(self.max_hops)])
        cmd.append(host)
        return cmd

    def kill(self) -> None:
        if self.troute:
            self.troute.kill()

    def trace(self, host: str, proto: str = 'icmp') -> list[Optional[str]]:
        logger.info('Traceroute requested using %s', proto)
        if proto == 'best':
            proto = self._get_best(ipv6=is_ipv6(host))
        if is_ipv6(host):
            cmd = self._ipv6_cmd(host, proto=proto)
        else:
            cmd = self._ipv4_cmd(host, proto=proto)
        logger.debug('Running traceroute using commandline %s', ' '.join(cmd))
        troute = self.troute = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, # nosec B603
                                                text=True, bufsize=1)

        if troute.stdout is None or troute.stderr is None:
            raise TracerouteError("Error initializing traceroute: unable to pipe stdout or stderr")

        result = self.parse_output(troute.stdout, host)
        troute.wait()
        # Don't show an error if we killed the trace ourselves (rcode -15)
        if troute.returncode not in [0, -9, -15]:
            raise TracerouteError(
                f"command '{' '.join(cmd)}' returned {troute.returncode}, stderr: {''.join(troute.stderr.readlines())}")
        troute.stdout.close()
        troute.stderr.close()
        return result

    def parse_output(self, output: IO[str], host: str) -> list[Optional[str]]:
        result = []
        starcount = 0
        for line in iter(output.readline, ''):
            ip = self.parse_line(line)
            if ip is None:
                starcount = starcount + 1
            else:
                starcount = 0
            result.append(ip)
            if starcount == self.giveup:
                logger.warning('%s non-responding hops in a row: terminating trace to %s', starcount, host)
                if self.troute is not None:
                    self.troute.terminate()
                return result
        return result

    @classmethod
    def capabilities(cls, ipv6: bool = False, privileged: Optional[bool] = None) -> set[str]:
        my_capabilities = cls._nonroot_capabilities
        if privileged or IS_PRIVILEGED:
            my_capabilities = cls._root_capabilities
        if ipv6:
            my_capabilities = my_capabilities & cls._ipv6_capabilities
        return my_capabilities

    def capabilities_for_host(self, host: str) -> set[str]:
        ipv6 = is_ipv6(host)
        capabilities = self.capabilities(ipv6=ipv6, privileged=IS_PRIVILEGED)
        return capabilities

    def parse_line(self, line: str) -> Optional[str]:
        """Parses a single traceroute line"""
        # Extracts ip from output like:
        # 1   *
        # 2   0.0.0.0   0 ms
        try:
            ip = line.strip().split()[1]
        except IndexError:
            ip = None
        if ip == '*':
            ip = None
        return ip


class BSDTraceroute(Traceroute):
    # This is an alias for the default traceroute
    ...


class LinuxTraceroute(Traceroute):
    _nonroot_capabilities = {'udp'}
    _root_capabilities = {'icmp', 'udp', 'tcp'}
    _ipv6_capabilities = {'icmp', 'udp'}

    def _ipv6_cmd(self, host: str, proto: str = 'icmp') -> list[str]:
        if proto == 'icmp':
            cmd = ["traceroute", "-6", "-I", "-n", "-q1", host]
        elif proto == 'tcp':
            cmd = ["traceroute", "-6", "-T", "-n", "-q1", host]
        else:
            cmd = ["traceroute", "-6", "-n", "-q1", host]
        return cmd

    def _ipv4_cmd(self, host: str, proto: str = 'icmp') -> list[str]:
        if proto == 'icmp':
            cmd = ["traceroute", "-4", "-I", "-n", "-q1", host]
        elif proto == 'tcp':
            cmd = ["traceroute", "-4", "-T", "-n", "-q1", host]
        else:
            cmd = ["traceroute", "-4", "-n", "-q1", host]
        return cmd

    def parse_output(self, output: IO[str], host: str) -> list[Optional[str]]:
        output.readline()  # Skip header line on linux
        return super().parse_output(output, host)


class WindowsTraceroute(Traceroute):
    _nonroot_capabilities = {'icmp'}
    _root_capabilities = {'icmp'}
    _ipv6_capabilities = {'icmp'}

    def _ipv6_cmd(self, host: str, proto: str = 'icmp') -> list[str]:
        cmd = ["tracert", "/6", "/d", "/h", "64", host]
        return cmd

    def _ipv4_cmd(self, host: str, proto: str = 'icmp') -> list[str]:
        cmd = ["tracert", "/4", "/d", "/h", "64", host]
        return cmd

    def parse_line_tracert(self, line: str) -> Optional[str]:
        """Parses a single tracert line"""
        # TODO: This should be double checked on a windows machine
        # Extracts ip from output like:
        # 1<tab>1ms<tab>1ms<tab>1ms<tab>0.0.0.0
        # 1<tab>*<tab>*<tab>*<tab>Request timed out
        ip = line.strip().split('\t')[4]
        if ip.startswith('Request'):
            return None
        return ip


def get_traceroute(system: Optional[str] = None, **kwargs: Any) -> Traceroute:
    if system is None:
        system = platform.system()

    implementations = {'Darwin': BSDTraceroute, 'OpenBSD': BSDTraceroute, 'Linux': LinuxTraceroute}
    implementation: Optional[Type[Traceroute]] = implementations.get(system)
    if implementation is None:
        implementation = LinuxTraceroute
    logger.debug('Running on system %s using implementation %s', system, implementation.__name__)
    return implementation(**kwargs)  # type: ignore


def traceroute(host: str, proto: str = "best", giveup: int = 5, pref: list[str] = ['icmp', 'udp', 'tcp']) -> list[Optional[str]]:
    implementation = get_traceroute()
    ipv6 = is_ipv6(host)
    logger.info('Traceroute requested using %s', proto)
    capabilities = implementation.capabilities(ipv6=ipv6, privileged=IS_PRIVILEGED)
    logger.debug('Traceroute implementation %s has capabilities %s', implementation.__class__.__name__,
                 str(capabilities))
    if proto == "best":
        cap_by_pref = [proto for proto in pref if proto in capabilities] + list(capabilities)
        proto = cap_by_pref[0]
        logger.debug('Selecting supported protocol type by order of preference ->  %s', proto)
    assert proto in capabilities, f'{proto} is not supported, supported protocols are {capabilities}'
    logger.debug('Traceroute to %s is using proto %s', host, proto)
    trace = implementation.trace(host, proto=proto)
    return trace


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    print('IPv4:', traceroute('sidnlabs.nl', proto='best'))
    print('IPv6:', traceroute('2600:1901:0:7947::', proto='best'))
