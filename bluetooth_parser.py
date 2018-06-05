"""A library to break down a btsnoop_hci.log from Android.

This version uses tshark and pyshark.
"""

import pyshark

from bluetooth_connection import *
from bluetooth_events import BluetoothEventFactory


def parse_connections(btsnoop_path):
  """Read the bt snoop log from the specified path and dissect the connection
  time.

  This function reads the Bluetooth snoop log and parse the log with
  connectivity events. The event start/finish time is returned in dict format.

  Args:
    btsnoop_path: str, the path of the bt snoop log from Android.
    This will significantly increase processing time.

  Returns:
    List of connections, sorted by ACL connection event start time.
  """
  cap = pyshark.FileCapture(input_file=btsnoop_path)
  # Divide connections by connection handle. ACL event will have connection
  # handle in the last packet

  connection_list = []

  acl_inquery_event = BluetoothEventFactory.create_event('acl create')
  acl_connect_event = BluetoothEventFactory.create_event('acl request')
  acl_event = None
  i = 0
  for packet in cap:
    i = i + 1
    setattr(packet, 'tshark_seq', i)
    # Check for existing connection
    for connection in connection_list:
      # Update will return True only when the packet is related to it.
      if connection.is_disconnected:
        continue
      elif connection.update(packet):
        break

    # Taking care of the new connection.
    acl_inquery_event.update(packet)
    acl_connect_event.update(packet)

    if acl_inquery_event.is_finished:
      acl_event = acl_inquery_event
    elif acl_connect_event.is_finished:
      acl_event = acl_connect_event
    if acl_event:
      print('Found new %s event, creating new connection' % acl_event.base_name)
      try:
        new_connection = BluetoothConnection(acl_event)
        connection_list.append(new_connection)
      except BluetoothConnectionError as ex:
        print('Failed to create new connection: %s' % ex)
      finally:
        acl_inquery_event = BluetoothEventFactory.create_event('acl create')
        acl_connect_event = BluetoothEventFactory.create_event('acl request')
        acl_event = None
  return connection_list


def connection_time_dissector(btsnoop_path):
  """Read the bt snoop log from the specified path and dissect the connection
  time.

  This function reads the Bluetooth snoop log and parse the log with
  connectivity events. The event start/finish time is returned in dict format.

  Args:
    btsnoop_path: str, the path of the bt snoop log from Android.
    This will significantly increase processing time.

  Returns:
    List of events, sorted by the event start time. ACL connection event is set
    as reference point (T = 0).
  """
  cap = pyshark.FileCapture(input_file=btsnoop_path)

  # There are two possible way to start ACL
  acl_inquery_event = BluetoothEventFactory.create_event('acl create')
  acl_connect_event = BluetoothEventFactory.create_event('acl request')
  a2dp_event = BluetoothEventFactory.create_event('a2dp')
  avrcp_event = BluetoothEventFactory.create_event('avrcp')
  # TODO: make RFCOMM event more generic.
  rfcomm20_event = BluetoothEventFactory.create_event('rfcomm ch20')
  rfcomm21_event = BluetoothEventFactory.create_event('rfcomm ch21')

  # Main event list, I expect all events here finish in a successful connection.
  event_list = [a2dp_event, avrcp_event]
  # RFCOMM channel 20 and 21 is Apollo/AGSA specific
  # event_list.extend([rfcomm20_event, rfcomm21_event]

  # Could have multiple SDP events, we put them in a list.
  sdp_list = [BluetoothEventFactory.create_event('sdp')]
  # Same with HFP
  hfp_list = [BluetoothEventFactory.create_event('hfp')]

  rfcomm_hfp_list = [BluetoothEventFactory.create_event('rfcomm hfp')]

  i = 0
  for packet in cap:
    i = i + 1
    setattr(packet, 'tshark_seq', i)
    all_done = True

    # ACL
    acl_inquery_event.update(packet)
    acl_connect_event.update(packet)

    if acl_inquery_event.is_finished:
      conn = BluetoothConnection(acl_inquery_event)
      conn.print_summary()

    if acl_connect_event.is_finished:
      conn = BluetoothConnection(acl_connect_event)
      conn.print_summary()

    # SDP
    sdp_event = sdp_list[-1]
    sdp_event.update(packet)
    if sdp_event.is_finished:
      sdp_list.append(BluetoothEventFactory.create_event('sdp'))

    # HFP
    hfp_event = hfp_list[-1]
    hfp_event.update(packet)
    if hfp_event.is_finished:
      hfp_list.append(BluetoothEventFactory.create_event('hfp'))

    # HFP for qualcomm
    rfcomm_hfp_event = rfcomm_hfp_list[-1]
    rfcomm_hfp_event.update(packet)
    if rfcomm_hfp_event.is_finished:
      rfcomm_hfp_list.append(BluetoothEventFactory.create_event('rfcomm hfp'))

    # Main events
    for event in event_list:
      event.update(packet)
      all_done = all_done and event.is_finished
    if all_done:
      # break
      pass

  print('Done at %d packet.' % i)

  # determine which ACL event to list
  acl_event_list = [acl_inquery_event]
  if acl_connect_event.is_finished:
    if event_list[0].start_time > acl_connect_event.start_time:
      acl_event_list += [acl_connect_event]
    else:
      acl_event_list.append(acl_connect_event)
  all_events = acl_event_list + event_list + sdp_list[:-1] + hfp_list[:-1]
  all_events = sorted(all_events, key=lambda event: event.start_time)

  return all_events
