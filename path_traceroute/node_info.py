#!/usr/bin/env python3

import asyncio
import ipaddress
import logging
import socket
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Union

import dns.resolver
import dns.reversename
import ipwhois  # type: ignore
import whois  # type: ignore

from path_traceroute.util.rpki import ROAChecker

MAX_WORKERS = 5

logging.basicConfig(
    format="%(asctime)s %(name)s: %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger('path_traceroute.node_info')
logger.setLevel(logging.INFO)

resolver = dns.resolver.Resolver()
roa_checker = ROAChecker()
try:
    dns.resolver.resolve('example.nl', 'a')
except Exception as e:
    logger.error('no usable dns resolver')
    raise e

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

hop_cache: dict[str, dict[str, Optional[str]]] = {}
hop_cache_expire: dict[float, list[str]] = {}


def use_our_resolver() -> None:
    resolver.nameservers = ['::1']
    resolver.port = 53535


def get_dis(hop: str) -> Optional[str]:
    """Retrieves the IP of the Domain Information Service for a certain hop"""
    # noinspection PyBroadException
    try:
        reverse_name = dns.reversename.from_address(hop)
        # Join rr.strings instead of just calling rr.to_text() since a TXT
        # record may consist of contain "multiple <character-string>s". Example:
        # $ dig +short txt redbarn.org
        # "v=spf1 " "redirect=_spf.tisf.net"
        # XXX decoding as ascii???
        txt_records = [b' '.join(rr.strings).decode('ascii') for rr in resolver.resolve(reverse_name, 'TXT').rrset]
        dis_records = [record for record in txt_records if record.startswith('v=DIS1')]

        if len(dis_records) == 0:
            return None
        else:
            # expect a TXT record in the form of "v=DIS1 ip=192.168.1.1"
            record = {}
            for kvpair in dis_records[-1].split():
                k, v = kvpair.split('=')
                record[k] = v
            return record.get('ip')
    except Exception:
        return None


def get_info(ip_address: str) -> dict[str, Optional[str]]:
    """Gathers information about a certain hop ip"""

    def is_private(ip: Optional[str]) -> bool:
        """Checks if an ip is RFC1918 or its ipv6 equivalent"""
        error: list[ValueError] = []
        if ip is None:
            return False

        addr: Union[None, ipaddress.IPv4Address, ipaddress.IPv6Address] = None
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError as value_error:
            error.append(value_error)

        if addr is not None:
            if addr.is_private:
                return True  # private ipv4
            return False  # nonprivate ipv4

        # now do ipv6
        try:
            addr = ipaddress.IPv6Address(ip)
        except ValueError as value_error:
            error.append(value_error)

        if addr is not None and addr.is_private:
            return True  # private ipv6
        if all(error) and len(error) > 1:
            # Only report if both ipv4 and ipv6 fail
            logger.exception(error[0])
            logger.exception(error[1])
        return False  # anything else

    def get_hostname(ip: Optional[str]) -> Optional[str]:
        """Retrieves the hostname for a certain ip"""
        if ip is None:
            return ip
        try:
            name, *_ = socket.gethostbyaddr(ip)
            return name
        except socket.herror:
            return ip

    def get_domain(ip: Optional[str]) -> Optional[str]:
        """Retrieves the domain.tld from a certain ip"""
        if ip is None:
            return ip
        try:
            flags = 0 | whois.NICClient.WHOIS_QUICK
            by_domain = whois.whois(ip, flags)
            domain = by_domain.domain_name
            if not domain:
                hostname = get_hostname(ip)
                if hostname is None:
                    return None
                elif hostname == ip:
                    return ip
                return '.'.join(hostname.split('.')[-2:])
            if isinstance(domain, list):
                return domain[0].lower()
            return domain.lower()
        except whois.parser.PywhoisError:
            return ip
        except ValueError:
            return ip

    def as_info(ip: Optional[str], empty: bool = False, try_whois: bool = False) -> dict[str, str]:
        """Retrieves AS (and some additional info) via whois for an IP"""

        def default_value() -> str:
            """Ad Asterisk"""
            return '*'

        empty_dict: dict[str, str] = defaultdict(default_value)
        if empty:
            return empty_dict

        if ip is None:
            return empty_dict

        obj = None

        try:
            obj = ipwhois.IPWhois(ip)
            # return obj.lookup_whois()
        except ValueError:
            pass

        if not obj:
            return empty_dict

        # first try to obtain info via RDAP
        try:
            return obj.lookup_rdap(depth=1)
        except (ipwhois.exceptions.IPDefinedError,
                ipwhois.exceptions.WhoisLookupError,
                ipwhois.exceptions.ASNParseError,
                ipwhois.exceptions.HTTPLookupError,
                ):
            pass
        except ipwhois.exceptions.HTTPRateLimitError as rate_limit:
            logger.error('got rate limited %s', rate_limit)
        except whois.parser.PywhoisError:
            pass
        except ConnectionResetError as conn_error:
            logger.exception(conn_error)

        if try_whois:
            # try to obtain info via whois
            try:
                return obj.lookup_whois(retry_count=0, asn_methods=['whois'])
            except (ipwhois.exceptions.IPDefinedError,
                    ipwhois.exceptions.WhoisLookupError,
                    ipwhois.exceptions.ASNParseError,
                    ipwhois.exceptions.HTTPLookupError
                    ):
                pass
            except whois.parser.PywhoisError:
                pass

        logger.debug('ipwhois lookup for %s failed', ip)
        return empty_dict

    if not is_private(ip_address):
        asn_info = as_info(ip_address)
    else:
        asn_info = as_info(ip_address, empty=True)
        asn_info['asn'] = 'private_ip'
        asn_info['asn_description'] = 'RFC1918/RFC4193'

    o = {'asn': asn_info['asn'],
         'hostname': get_hostname(ip_address),
         'country': asn_info['asn_country_code'],
         'cidr': asn_info['asn_cidr'],
         'description': asn_info['asn_description'],
         'domain': get_domain(ip_address),
         'dis': get_dis(ip_address),
         'roa': 'valid' if roa_checker.roa_valid(asn_info['asn'], asn_info['asn_cidr']) else 'invalid',
         'ip': ip_address
         }

    return o


async def hop_info(ip: str, cache_ttl: int = 3600) -> dict[str, Optional[str]]:
    """Shim to cache the get_info call
       We run get_info in a threadpool since it contants syncronous network
       dependent code, we don't want to become unresponsive.
    """
    global hop_cache, hop_cache_expire

    # Expire hops that have been in cache longer than cache_ttl
    now = time.time()
    expired_hops = [hop for exp_time, hops in hop_cache_expire.items() for hop in hops if exp_time < now]
    expired_times = [exp_time for exp_time in hop_cache_expire.keys() if exp_time < now]
    for hop in list(set(expired_hops)):
        if hop in hop_cache.keys():
            del hop_cache[hop]
    for exp_time in expired_times:
        del hop_cache_expire[exp_time]
    logger.info('Amount of cached hops: %s', len(hop_cache))

    result = hop_cache.get(ip)

    if result:
        logger.info(f'hop_info for {ip} is retrieved from cache')
        return result

    logger.info(f'hop_info for {ip} is not cached getting info')
    loop = asyncio.get_running_loop()
    info_thread = loop.run_in_executor(executor, get_info, ip)
    start = time.clock_gettime(time.CLOCK_MONOTONIC)
    result = await info_thread
    if result['asn'] != '*' and result['asn'] != "NA":
        # Well there is something sensible here so lets cache
        hop_cache[ip] = result
        hop_cache_expire.setdefault(time.time() + cache_ttl, []).append(ip)
    end = time.clock_gettime(time.CLOCK_MONOTONIC)
    logger.info('get_info information gathering for %s took %.2fs', ip, (0.0 + end - start))
    return result


async def main() -> None:
    hop = '35.190.27.69'
    hop6 = '2600:1901:0:7947::'
    print(await hop_info(hop))
    print(await hop_info(hop6))


if __name__ == '__main__':
    """Run the main function asynchronously"""
    asyncio.run(main())
