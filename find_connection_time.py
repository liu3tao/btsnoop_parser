"""A library to break down a btsnoop_hci.log from Android.

This version uses tshark and pyshark.
"""

import json
import argparse
from bluetooth_parser import *


def _calc_time_table_from_events(event_list):
  """Calculate the time table from list of events."""
  time_table = []
  start_time = event_list[0].start_time
  if start_time is None:
    print('The first ACL event is not finished!')
    start_time = 0.0
  for event in event_list:
    name = event.name
    if event.finish_time is None:
      name += ' (Not Finished)'
    start_delta = event.start_time - start_time if event.start_time else -1.0
    finish_delta = event.finish_time - start_time if event.finish_time else -1.0
    row = (name,
           start_delta,
           finish_delta,
           event.start_time,
           event.finish_time)
    time_table.append(row)
  return time_table


def main(btsnoop_path, print_summary=False, use_json=False):
  connection_list = parse_connections(btsnoop_path)
  i = 0
  json_list = []
  for connection in connection_list:
    i += 1
    time_table = _calc_time_table_from_events(connection.get_events())
    if use_json:
      json_list.append({'bt_addr': connection.bt_addr,
                        'time_table': time_table})
    else:
      print('\nConnection %d' % i)
      connection.print_summary()
      print('Event Name\tDelta Start Time\tDelta Elapsed Time\tStart Time\tFinish Time')
      for row in time_table:
        print('%s\t%0.6f\t%0.6f\t%0.6f\t%0.6f' % row)
      if print_summary:
        for evt in connection.get_events():
          evt.print_summary()
  if use_json:
    print('\n=== START JSON ===')
    print(json.dumps(json_list))
    print('=== END JSON ===')


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description = 'btsnoop parser main')
  parser.add_argument('path', help='btsnoop_hci.log path')
  parser.add_argument('-v', '--verbose', help='verbosity output',
                      action='store_true')
  parser.add_argument('-j', '--json_output',
                      help='Output in JSON format. Verbose will be disabled.',
                      action='store_true')
  args = parser.parse_args()
  main(args.path, args.verbose, args.json_output)

