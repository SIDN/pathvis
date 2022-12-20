
from datetime import datetime, timedelta
import json
import logging
import os
import requests

from typing import Any, Optional, Union
from typing import Optional

logger = logging.getLogger('path_traceroute.rpki')

# File to store rpki fetch results in
VRPS_FILENAME = os.path.abspath("vrps.json")
# Default url to fetch rpki data
VRPS_URL = "https://console.rpki-client.org/vrps.json"
# When to fetch new data
VRPS_EXPIRE_DAYS = 7

class ROAChecker():
    def __init__(self, vrps_filename: Optional[str]=None, vrps_url: Optional[str]=None) -> None:
        self.vrps_filename = vrps_filename if vrps_filename is not None else VRPS_FILENAME
        self.vrps_url = vrps_url if vrps_url is not None else VRPS_URL
        self.data: dict[str, Any] = {}
        
        self._load_vrps()

    def _download_vrps(self) -> None:
        logger.info(f"Downloading VRPS data from {self.vrps_url}")
        response = requests.get(self.vrps_url)
        self.data = response.json()
        logger.info(f"Storing VRPS data in {self.vrps_filename}")
        with open(self.vrps_filename, 'w') as outfile:
            json.dump(self.data, outfile, indent=2)

    def _load_vrps(self) -> None:
        if os.path.exists(self.vrps_filename):
            logger.info(f"Loading VRPS data from {self.vrps_filename}")
            with open(self.vrps_filename, 'r') as infile:
                self.data = json.load(infile)
            now = datetime.now()
            build_time = datetime.strptime(self.data['metadata']['buildtime'], '%Y-%m-%dT%H:%M:%SZ')
            if build_time + timedelta(days=VRPS_EXPIRE_DAYS) > now:
                return
            logger.info("VRPS data expired, download again")
        self._download_vrps()

    def roa_valid(self, asn: Union[int, str], prefix: str) -> bool:
        if not asn or asn == '*':
            return False
        if not prefix or prefix == '*':
            return False
        valid_prefixes = list((str(roa['asn']), str(roa['prefix'])) for roa in self.data['roas'])
        return (asn, prefix) in valid_prefixes
