"""A library to break down a btsnoop_hci.log from Android.

This version uses tshark and pyshark.
"""

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
           finish_delta)
    time_table.append(row)
  return time_table


def main(btsnoop_path, print_summary=False):
  connection_list = parse_connections(btsnoop_path)
  for connection in connection_list:
    print('=== Connection ===')
    connection.print_summary()
    print('Event Name\tStart Time\tElapsed Time')
    time_table = _calc_time_table_from_events(connection.get_events())
    for row in time_table:
      print('%s\t%0.6f\t%0.6f' % row)
    if print_summary:
      for evt in connection.get_events():
        evt.print_summary()


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description = 'btsnoop parser main')
  parser.add_argument('path', help='btsnoop_hci.log path')
  parser.add_argument('-v', '--verbose', help='verbosity output',
                      action='store_true')
  args = parser.parse_args()
  main(args.path, args.verbose)

