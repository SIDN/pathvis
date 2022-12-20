import socket
import ipaddress
import datetime
from datetime import timezone
from typing import Optional

def is_valid_ip_address(address: str, version: Optional[int]=None) -> bool:
    assert version in [4, 6, None], "version can be either 4 for ipv4 or 6 for ipv6"
    try:
        ip = ipaddress.ip_address(address)
        if version is None:
            return True
        if version == ip.version:
            return True
    except ValueError:
        pass
    return False

def get_local_ip() -> str:
    '''Gets a publicly routable IP address'''
    #multiple methods for this, this one pretends to use google :P
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
    local_ip_address = s.getsockname()[0]
    s.close()
    return local_ip_address

def get_utc_time() -> float:
    '''Gets current time in UTC'''
    dt = datetime.datetime.now(timezone.utc)
    utc_time = dt.replace(tzinfo=timezone.utc)
    utc_timestamp = utc_time.timestamp()
    return utc_timestamp
