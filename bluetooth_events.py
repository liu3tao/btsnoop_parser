"""A set of Bluetooth events."""

from event_base import *

# Some constants for reoccurring strings.
EVENT_NAME = 'event_name'
START_FILTER = 'start_filter'
FINISH_FILTER = 'finish_filter'
RELEVANT_FILTER = 'relevant_filter'
KEY_FIELDS = 'key_fields'

# A dict for defining filters for supported events.
# Key: short name of the event
# Value: dict of <event name>, <start filter>, <finish filter>, <relevant filter>
# TODO(liuta): Better to move the data to a separate config file.
_BLUETOOTH_EVENT_FILTERS = {
  'acl inquery': {
    EVENT_NAME: 'bluetooth acl inquery',
    START_FILTER: [('bthci_cmd', 'opcode', 0x405)],
    FINISH_FILTER: [('bthci_evt', 'code', 0x03),
                    ('bthci_evt', 'status', 0x00)],
    RELEVANT_FILTER: None
  },
  'acl connect': {
    EVENT_NAME: 'bluetooth acl connect',
    START_FILTER: [('bthci_evt', 'code', 0x04)],
    FINISH_FILTER: [('bthci_evt', 'code', 0x03),
                    ('bthci_evt', 'status', 0x00)],
    RELEVANT_FILTER: None
  },
  'a2dp': {
    EVENT_NAME: 'Bluetooth A2DP',
    START_FILTER: [('btavdtp', 'message_type', 0x00),
                   ('btavdtp', 'signal_id', 0x01)],
    FINISH_FILTER: [('btavdtp', 'message_type', 0x02),
                    ('btavdtp', 'signal_id', 0x06)],
    RELEVANT_FILTER: [('btavdtp', None, None)]
  },
  'hfp': {
    EVENT_NAME: 'Bluetooth HFP',
    START_FILTER: [('bthfp', 'command_line_prefix', 'AT')],
    FINISH_FILTER: [('bthfp', 'at_cmd.type', 0x0d0a)],
    RELEVANT_FILTER: [('bthfp', None, None)],
    KEY_FIELDS: [('bthfp', 'bthfp.at_cmd', KeyFieldSpec.PKT_LOCATION_START),
                 ('bthfp', 'bthfp.at_cmd', KeyFieldSpec.PKT_LOCATION_FINISH)]
  },
  'avrcp': {
    EVENT_NAME: 'Bluetooth AVRCP',
    START_FILTER: [('btavrcp', 'ctype', 0x3),
                   ('btavrcp', 'notification.event_id', 0x0d)],
    FINISH_FILTER: [('btavrcp', 'ctype', 0xf),
                    ('btavrcp', 'notification.event_id', 0x0d)],
    RELEVANT_FILTER: [('btavrcp', None, None)]
  },
  'rfcomm ch20': {
    EVENT_NAME: 'Bluetooth RFCOMM CH20',
    START_FILTER: [('btrfcomm', 'mcc.cmd', 0x20),
                   ('btrfcomm', 'mcc.channel', 20)],
    FINISH_FILTER: [('btrfcomm', 'mcc.cmd', 0x38),
                    ('btrfcomm', 'mcc.channel', 20)],
    RELEVANT_FILTER: [('btrfcomm', None, None)]
  },
  'rfcomm ch21': {
    EVENT_NAME: 'Bluetooth RFCOMM CH21',
    START_FILTER: [('btrfcomm', 'mcc.cmd', 0x20),
                   ('btrfcomm', 'mcc.channel', 21)],
    FINISH_FILTER: [('btrfcomm', 'mcc.cmd', 0x38),
                    ('btrfcomm', 'mcc.channel', 21)],
    RELEVANT_FILTER: [('btrfcomm', None, None)]
  },
  'sdp': {
    EVENT_NAME: 'Bluetooth SDP',
    START_FILTER: [('btsdp', 'pdu', 0x06),
                   ('btsdp', 'continuation_state', 'Continuation State: no (00)')],
    FINISH_FILTER: [('btsdp', 'pdu', 0x07),
                    ('btsdp', 'continuation_state', 'Continuation State: no (00)')],
    RELEVANT_FILTER: [('btsdp', None, None)],
    KEY_FIELDS: [('btsdp', 'service_search_pattern', 0)]
  },
  'avrcp capability': {
    EVENT_NAME: 'Bluetooth AVRCP GetCapabilities',
    START_FILTER: [('btavrcp', 'ctype', 0x1),
                   ('btavrcp', 'capability', 0x03)],
    FINISH_FILTER: [('btavrcp', 'ctype', 0xc),
                    ('btavrcp', 'capability', 0x03)],
    RELEVANT_FILTER: [('btavrcp', None, None)]
  },
  'rfcomm hfp': {
    EVENT_NAME: 'Bluetooth HFP RFCOMM',
    START_FILTER: [('btrfcomm', 'channel', 3)],
    FINISH_FILTER: [('btrfcomm', 'len', 0)],
    RELEVANT_FILTER: [('bthfp', None, None)]
  }
}


class BluetoothEventFactory(object):
  """Create predefined Bluetooth event."""

  @classmethod
  def create_event(cls, event_name):
    """Create Bluetooth event object based on the event short name.

    Args:
      event_name: str, short event name like ACL, A2DP, etc. Case insensitive.

    Returns:
      ConnectivityEventBase (or its subclass) objects with corresponding
      filters for the event.

    Raises:
      NotImplementedError if the specified event is not implemented.
    """
    if event_name.lower() in _BLUETOOTH_EVENT_FILTERS:
      filter_dict = _BLUETOOTH_EVENT_FILTERS[event_name.lower()]
      return ConnectivityEventBase(
        event_name=filter_dict[EVENT_NAME],
        start_filer=PacketFilter(filter_dict[START_FILTER]),
        finish_filter=PacketFilter(filter_dict[FINISH_FILTER]),
        relevant_filter=PacketFilter(filter_dict[RELEVANT_FILTER]),
        key_fields=filter_dict.get(KEY_FIELDS, None)
      )
    else:
      raise NotImplementedError('The specified event %s is not implemented.'
                                % event_name)
