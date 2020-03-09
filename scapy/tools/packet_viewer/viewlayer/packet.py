from uuid import UUID

from scapy.packet import Packet
from urwid import Text

from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior


class GuiPacketNonCAN(Text):
    """
    A wrapper class which makes the packet's attributes easily accessible
    and has a reference to the packet in form of a uuid.
    """

    def __init__(self, packet: Packet, uuid: UUID):
        """
        :param packet: a packet, which attributes are copied into this wrapper class
        :type packet: scapyPacket
        :param uuid: a unique identifier to retrieve the original packet from the data layer
        :type uuid: UUID
        """
        self._selectable: bool = True  # necessary, so that entries in the packetView can be selected by mouse click
        # not shown in GUI, but necessary to get the original packet from the data layer
        self.uuid: UUID = uuid
        self.field_names: list = [field.name for field in packet.fields_desc]
        self.fields: dict = {field_name: getattr(packet, field_name) for field_name in self.field_names}

        text: str = type(packet).__name__ + ": "

        for item in self.fields.items():
            text += str(item)
        text += "\n"

        super(GuiPacketNonCAN, self).__init__([("cursor", u">> "), text])


class GuiPacket(Text):
    """
    A wrapper class which makes the packet's attributes easily accessible
    and has a reference to the packet in form of a uuid.
    """

    def __init__(self, packet: Packet, behavior: DefaultBehavior):
        """
        :param packet: a packet, which attributes are copied into this wrapper class
        :type packet: CAN
        """
        self._selectable: bool = True  # necessary, so that entries in the packetView can be selected by mouse click
        self.packet = packet

        # not needed at the moment
        # count, time_variance = get_count_and_variance(packet, info)

        text: str = behavior.get_packet_formatted(packet)

        super(GuiPacket, self).__init__([("cursor", u">> "), text])
