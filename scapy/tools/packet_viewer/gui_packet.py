from urwid import Text

from scapy.packet import Packet


class GuiPacket(Text):
    """
    A wrapper class which makes the packet's attributes easily accessible
    and has a reference to the packet in form of a uuid.
    """

    def __init__(
        self,
        packet,  # type: Packet
        *args,
        **kwargs
    ):
        """
        :param packet: a packet, which attributes are copied into this wrapper class
        :type packet: CAN
        """
        # necessary, so that entries in the packetView can be selected by mouse click
        self._selectable = True  # type: bool
        self.packet = packet

        # not needed at the moment
        # count, time_variance = get_count_and_variance(packet, info)

        super(GuiPacket, self).__init__(*args, **kwargs)

    def keypress(self, size, key):
        # Since this text is selectable, it has to provide a keypress method.
        return key
