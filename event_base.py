"""A collection of network events for BT snoop parser."""

import time


class EventState(object):
  """A container class for event state constants."""
  NOT_STARTED = 0
  IN_PROGRESS = 1
  FINISHED = 2
  ERROR = -1


class KeyFieldSpec(object):
  """A container class for key fields"""
  PKT_LOCATION_START = 0
  PKT_LOCATION_FINISH = -1
  PKT_LOCATION_ANY = 1


class PacketFilter(object):
  """A packet filter to filter packet from pyshark."""

  def __init__(self, criteria_list):
    """Create a filter based on the criteria.

    Arg:
      criteria_list: list of 3-element tuples, each tuple is one filter
        criteria. The filter criteria tuple contains 3 values:
        (layer name, field name, expected value)
        incoming packets need to have expected value in the layer.field to pass.
    """
    self._criteria = []
    if criteria_list:
      for layer_name, field_name, expected_value in criteria_list:
        self._criteria.append((layer_name, field_name, expected_value))

  def eval(self, packet):
    """Filter the packet based on the criteria list.

    Args:
      packet: packet object from pyshark.

    Return: True if the packet pass the filter. False otherwise.
    """
    # Empty filter will not allow any packet.
    if not self._criteria:
      return False

    ret = True
    for layer_name, field_name, expected_value in self._criteria:
      if layer_name in packet:
        # we have got the layer. Skip if no field name specified.
        if field_name is None:
          break
        value = packet[layer_name].get(field_name)
        # Check if we have the specified field.
        if value is None:
          ret = False
          break
        else:
          # Skip further checking if the expected value is not specified.
          if expected_value is None:
            break
          # Convert string to integer values
          elif isinstance(expected_value, int):
            try:
              value = int(value, 0)  # enable hex prefix-guessing
            except ValueError:
              ret = False
              break
          if value != expected_value:
            ret = False
            break
      else:
        ret = False
        break
    return ret

  @property
  def is_empty(self):
    return not self._criteria


class ConnectivityEventBase(object):
  """A generic event state machine for tracking connectivity related events."""

  def __init__(self, event_name, start_filer, relevant_filter, finish_filter,
               key_fields=None):
    """
    Args:
      event_name: str, name of the event.
      start_filer: PacketFilter, filter the start packet.
      relevant_filter: PacketFilter, filter relevant packets.
      finish_filter: PacketFilter, filter the finish packet.
      key_fields:
        list of 3-element tuples specifying the key fields of the event.
        The value of the key fields can be used to ID the event. Format:
        (layer name, field name, packet index)
        packet index is the 0-based index for the relevant packet list,
        layer name and field name follows wireshark definition.
    """
    self._state = EventState.NOT_STARTED
    self._event_start_time = None  # start timestamp
    self._event_finish_time = None  # finish timestamp
    self._relevant_packets = []  # list of relevant packets. In string format.
    self._event_name = event_name
    self._start_filter = start_filer
    self._relevant_filter = relevant_filter
    self._finish_filter = finish_filter
    self._key_fields = key_fields
    self._key_field_values = []

  @property
  def base_name(self):
    return self._event_name

  @property
  def name(self):
    if self._key_field_values:
      return self.base_name + ' (%s)' % '; '.join(self._key_field_values)
    else:
      return self.base_name

  @property
  def is_finished(self):
    return self._state == EventState.FINISHED

  @property
  def state(self):
    return self._state

  @property
  def start_time(self):
    return self._event_start_time

  @property
  def finish_time(self):
    return self._event_finish_time

  @property
  def key_field_values(self):
    """Returns a list of keyfield values."""
    return self._key_field_values

  def _add_relevant_packet(self, packet, is_start=False, is_finish=False):
    """Append relevant packets to local cache.
    Args:
      packet: the packet object from pyshark.
      is_start: bool, True only if the packet is the first of the event.
      if_finish: bool, True only if the packet is the last of the event.
    """
    seq = getattr(packet, 'tshark_seq')
    summary_line = getattr(packet, 'summary_line', None)
    self._relevant_packets.append((seq, summary_line, str(packet)))
    # Now check if the packet has key field.
    if self._key_fields:
      for layer_name, field_name, pkt_spec in self._key_fields:
        if ((pkt_spec == KeyFieldSpec.PKT_LOCATION_ANY) or
            (pkt_spec == KeyFieldSpec.PKT_LOCATION_START and is_start) or
            (pkt_spec == KeyFieldSpec.PKT_LOCATION_FINISH and is_finish)):
          if layer_name in packet:
            value = str(packet[layer_name].get(field_name))
            if value:
              self._key_field_values.append(value)

  def _move_to_next_state(self):
    if self._state == EventState.NOT_STARTED:
        self._state = EventState.IN_PROGRESS
    elif self._state == EventState.IN_PROGRESS:
      self._state = EventState.FINISHED

  def _set_start_time(self, timestamp=None):
    if timestamp is None:
      timestamp = time.time()
    self._event_start_time = timestamp

  def _set_finish_time(self, timestamp=None):
    if timestamp is None:
      timestamp = time.time()
    self._event_finish_time = timestamp

  def update(self, packet):
    """Check the new packet and see if we want to update the state.

    Will cover start/finish. The error logic needs to be implemented in
    subclasses.
    """
    if self._state == EventState.NOT_STARTED:
      if self._start_filter and self._start_filter.eval(packet):
        self._set_start_time(float(packet.sniff_timestamp))
        # Need to check if the event contains only one packet
        finish = True if self._finish_filter.is_empty else False
        self._add_relevant_packet(packet, is_start=True, is_finish=finish)
        self._move_to_next_state()
        if finish:
          self._set_finish_time(float(packet.sniff_timestamp))
          self._move_to_next_state()
    elif self._state == EventState.IN_PROGRESS:
      if self._finish_filter and self._finish_filter.eval(packet):
        self._set_finish_time(float(packet.sniff_timestamp))
        self._add_relevant_packet(packet, is_finish=True)
        self._move_to_next_state()
      elif self._relevant_filter and self._relevant_filter.eval(packet):
        self._add_relevant_packet(packet)

  def print_summary(self, verbose=False):
    """Get a result summary"""
    if self._state == EventState.NOT_STARTED:
      print('Event %s not started.' % self.name)
    elif self._state == EventState.IN_PROGRESS:
      print('Event %s started at T+%f, not finished.' %
            (self.name, self._event_start_time))
    elif self._state == EventState.FINISHED:
      print('Event %s started at T+%f, finished at T+%f, total %f seconds.' %
            (self.name, self._event_start_time, self._event_finish_time,
             self._event_finish_time - self._event_start_time))
    elif self._state == EventState.ERROR:
      print('Parsing error')

    pkt_list = ', '.join([str(packet_seq)
                          for packet_seq, _, _ in self._relevant_packets])
    print('%d relevant packets found, index %s' %
          (len(self._relevant_packets), pkt_list))
    if verbose:
      for packet_seq, summary_line, packet_str in self._relevant_packets:
        if summary_line:
          print('Packet #%d\n%s\n' % (packet_seq, summary_line))
        else:
          print('Packet #%d\n%s\n' % (packet_seq, packet_str))
