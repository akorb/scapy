from scapy.packet import Packet
from urwid import Text


class GuiPacket(Text):
    """
    A wrapper class which makes the packet's attributes easily accessible
    and has a reference to the packet in form of a uuid.
    """

    def __init__(self, packet: Packet, *args, **kwargs):
        """
        :param packet: a packet, which attributes are copied into this wrapper class
        :type packet: CAN
        """
        self._selectable: bool = True  # necessary, so that entries in the packetView can be selected by mouse click
        self.packet = packet

        # not needed at the moment
        # count, time_variance = get_count_and_variance(packet, info)

        super(GuiPacket, self).__init__(*args, **kwargs)
