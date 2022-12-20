#!/usr/bin/env python3

import argparse
import asyncio
import json

import websockets


async def ws_client(output_json, changes, quiet):
    async with websockets.connect('ws://localhost:8765') as websocket:
        while True:
            trace_str = await websocket.recv()
            try:
                trace = json.loads(trace_str)
                if trace['change'] or not changes:
                    if output_json:
                        print(trace_str)
                    else:
                        if quiet:
                            print(trace['destination'], "changed" if trace['change'] else "nochange",
                                  "new" if trace['new'] else "old", len(trace['trace']))
                        else:
                            print(trace)
            except json.decoder.JSONDecodeError:
                print(trace_str)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--changes', action='store_true', help='only dump changes')
    parser.add_argument('-j', '--json', action='store_true', help='output JSON instead of Python structure')
    parser.add_argument('-q', '--quiet', action='store_true', help='less verbose output')
    args = parser.parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(ws_client(args.json, args.changes, args.quiet))


if __name__ == '__main__':
    main()
