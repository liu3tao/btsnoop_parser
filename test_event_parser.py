"""Unit test for BT snoop log dissector."""

import unittest
from bluetooth_parser import connection_time_dissector


class ConnectionEventTest(unittest.TestCase):
  def test_connection_events(self):
    expected_events = [
      'Bluetooth ACL',
      'Bluetooth AVRCP',
      'Bluetooth RFCOMM CH21',
      'Bluetooth RFCOMM CH20'
    ]
    btsnoop_path = 'btsnoop_hci.log'
    event_list = connection_time_dissector(btsnoop_path)
    name_list = [event.name for event in event_list]
    for evt in expected_events:
      self.assertIn(evt, name_list)


if __name__ == '__main__':
  unittest.main()
