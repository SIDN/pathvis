import datetime
import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Generator, Iterable

MAX_ITEMS = 5000
resolve_dict: dict[str, list[str]] = OrderedDict()
running: threading.Event = threading.Event()
running.set()


class read_dnsmasq_log(object):
    '''Context manager that reads and parses the log'''

    def __init__(self, file_name: str) -> None:
        self.file_obj = open(file_name, 'r')
        self._open_queries: dict[int, list[list[str]]] = {}
        self._request_times: list[tuple[datetime.datetime, int]] = []

    def __enter__(self) -> Generator[tuple[Any, list[Any]], Any, None]:
        return self._parser(self._read_and_follow())

    def __exit__(self, type: type, value: Any, traceback: Any) -> None:
        self.file_obj.close()

    def _evict_queries(self, current_date: datetime.datetime) -> None:
        '''Evicts queries from open_queries and request_times that are older than current_date'''
        for num, entry in enumerate(self._request_times):
            time, qid = entry
            if time + datetime.timedelta(seconds=10) < current_date:
                if qid in self._open_queries:
                    del self._open_queries[qid]
                del self._request_times[num]

    def _read_and_follow(self) -> Iterable[str]:
        '''Reads file but keeps it open for reading new lines'''
        while True:
            line = self.file_obj.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

    def _parse_datetime(self, line: list[str]) -> datetime.datetime:
        '''Parses the datetime in the logfile'''
        datestr = " ".join(line[:3])
        result = datetime.datetime.strptime(datestr, "%b %d %H:%M:%S").replace(year=datetime.datetime.today().year)
        return result

    def _get_cnames(self, query_result: list[list[str]]) -> list[str]:
        '''Collects cnames from multi line query response'''
        cnames = []
        for parts in query_result:
            if parts[9] == '<CNAME>':
                cnames.append(parts[7])
        return cnames

    def _parser(self, lines: Iterable[str]) -> Generator[tuple[Any, list[Any]], Any, None]:
        '''Multiline parsing of the logfile'''
        for line in lines:
            line_parts = line.split()
            if len(line_parts) < 4:
                continue
            try:
                query_id = int(line_parts[4])
                if query_id not in self._open_queries:
                    # Query is new
                    self._open_queries[query_id] = []
                    self._request_times.append((self._parse_datetime(line_parts), query_id))
                else:
                    pass
                if line_parts[6] in ['cached', 'reply']:
                    if line_parts[9] in ['NXDOMAIN', 'NODATA', 'NODATA-IPv6', 'SERVFAIL', '0.0.0.0', '<HTTPS>', # nosec B104
                                         'NODATA-IPv4', 'duplicate']:
                        pass
                    elif line_parts[9] == '<CNAME>':
                        pass
                    else:
                        cnames = self._get_cnames(self._open_queries[query_id])
                        yield (line_parts[9], [*cnames, line_parts[7]])
                    self._open_queries[query_id].append(line_parts)
            except ValueError as e:
                continue
            self._evict_queries(self._parse_datetime(line_parts))


def reader(filename: str = '/tmp/query.log', max_items: int = MAX_ITEMS, silent: bool = True) -> None: # nosec B108
    with read_dnsmasq_log(filename) as reader:
        for ip, names in reader:
            if not running.is_set():
                return
            if ip in resolve_dict:
                # remove to update posistion in ordereddict
                del resolve_dict[ip]
            if len(resolve_dict) >= max_items:
                resolve_dict.popitem()
            resolve_dict[ip] = names
            if not silent:
                logging.debug(resolve_dict)


def lookup(ip: str) -> list[str]:
    return resolve_dict.get(ip, [])


if __name__ == '__main__':
    t = threading.Thread(target=reader, args=['/tmp/query.log'], kwargs={'silent': True}, daemon=True) # nosec B108
    t.start()
    print('Running for 3 seconds')
    print('8.8.8.8 =', lookup('8.8.8.8'))
    time.sleep(3)
    running.clear()
    print('end')
