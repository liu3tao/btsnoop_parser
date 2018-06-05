"""Define connection in Bluetooth. A connection contains multiple BT events,
starting with ACL connect event and optionally ACL disconnect event."""


from bluetooth_events import _BLUETOOTH_EVENT_FILTERS as BT_EVENTS
from bluetooth_events import BluetoothEventFactory


def _convert_handle_to_int(handle_hex_str):
  """Helper function to convert hex string from tshark to int value.

  Args:
    handle_hex_str: hex string of the connection handle.
  Returns:
    non-zero int value of connection handle. Returns None if conversion failed.
  """
  conn_handle = None
  try:
    conn_handle = int(handle_hex_str, 0)
  except ValueError:
    pass
  return conn_handle


def get_connection_handle(packet):
  """Helper function to get connection handler from packet. Understand HCI CMD,
  HCI EVT and HCI ACL packets.

  Args:
    packet: packet object from pyshark.
  Returns:
    int value of connection handler. If the packet doesn't have connection
    handler or not understandable, will return None.
  """
  handle = handle_str = None
  if 'bthci_acl' in packet:
    handle_str = packet['bthci_acl'].get('chandle')
  elif 'bthci_evt' in packet:
    handle_str = packet['bthci_evt'].get('connection_handle')
  elif 'bthci_cmd' in packet:
    handle_str = packet['bthci_cmd'].get('connection_handle')
  if handle_str:
    handle = _convert_handle_to_int(handle_str)
  return handle


class BluetoothConnectionError(Exception):
  pass


class BluetoothConnection(object):
  """Represents a Bluetooth connection.
  This class maintains a list of events that happened during the connection."""
  def __init__(self, acl_connect_event):
    """Create a new connection with ACL connect event.

    Args:
      acl_connect_event: the Bluetooth ACL connect event.
    """
    if len(acl_connect_event.key_field_values) < 2:
      raise (BluetoothConnectionError(
        'Invalid ACL connection event, cannot create connection.'))
    conn_handle = _convert_handle_to_int(acl_connect_event.key_field_values[0])
    if conn_handle is None:
      raise(BluetoothConnectionError(
        'Invalid ACL connection handle, cannot create connection.'))

    self.acl_connect_event = acl_connect_event
    self._connection_handle = conn_handle
    self._bt_addr = acl_connect_event.key_field_values[1]
    # A dict of event list, key: event type, value: list of event of this type
    self.event_lists = {}
    # create one event list for each type, excluding ACL connect events.
    for evt_type in BT_EVENTS:
      if 'acl ' not in evt_type:
        self.event_lists[evt_type] = [BluetoothEventFactory.create_event(
          evt_type)]
    # The one and only disconnect event.
    self.acl_disconnect_event = BluetoothEventFactory.create_event(
      'acl disconnect')

  def update(self, packet):
    """Update the connection with new packets
    Args:
      packet: the packet object from pyshark.

    Returns:
      True if the connection is open and the packet is a part of the connection.
      False otherwise.
    """
    # first make sure the connection is open.
    if self.is_disconnected:
      return False
    # check if the packet belongs to connection
    handle = get_connection_handle(packet)
    # Now we check if the connection handle matches.
    if handle is None or handle != self._connection_handle:
      return False
    # We found a packet belongs to the connection, update the events
    for evt_type in self.event_lists:
      evt = self.event_lists[evt_type][-1]
      evt.update(packet)
      if evt.is_finished:
        self.event_lists[evt_type].append(
          BluetoothEventFactory.create_event(evt_type))
    # Now check for disconnect event.
    self.acl_disconnect_event.update(packet)
    if self.acl_disconnect_event.is_finished:
        print('Disconnected! handle = %s' % hex(handle))
    return True

  def get_events(self):
    """Returns list of events so far, sorted by event start time."""
    all_events = []
    for evt_type in self.event_lists:
      all_events.extend(self.event_lists[evt_type][:-1])
    all_events = sorted(all_events, key=lambda event: event.start_time)
    # add ACl events
    all_events = [self.acl_connect_event] + all_events
    if self.acl_disconnect_event.is_finished:
      all_events += [self.acl_disconnect_event]
    return all_events

  @property
  def is_disconnected(self):
    if self.acl_disconnect_event:
      return self.acl_disconnect_event.is_finished
    else:
      return False

  def print_summary(self):
    """Print a summary of the events in this connection."""
    print('Connection handle {}, BT addr {},{} disconnected.'.format(
      hex(self._connection_handle), self._bt_addr,
      '' if self.is_disconnected else ' not'))
