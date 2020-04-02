from urwid import Button, ListBox, SimpleFocusListWalker, Pile, LineBox

from scapy.tools.packet_viewer.custom_views import MessageDetailsData
from scapy.tools.packet_viewer.gui_packet import Packet, GuiPacket


# TODO: Close button muss wo anders hin
class StatisticAnalysis(ListBox):
    def __init__(
        self,
        main_window,
        packet,  # type: Packet
        message_details,  # type: MessageDetailsData
    ):
        """
        :param packet: packet, which is currently selected and can be edited within this menu
        :type packet: Packet
        """
        self.main_window = main_window
        body = SimpleFocusListWalker(
            [
                message_details.header,
                packet,
                message_details.detail_view_header,
                message_details.byte_heat_map,
                message_details.bit_heat_map,
                message_details.corr_coef,
                Button("close", self.close),
            ]
        )  # type: SimpleFocusListWalker
        super(StatisticAnalysis, self).__init__(body)

    def close(self, _button):
        """
        Exchanges this menu with the packetview.
        :param _button: required to catch the callback argument
        :type _button: Any
        :return: None
        """
        self.main_window.body = self.main_window.view_stack.pop()

    def keypress(self, size, key):
        """
        Handles key-presses.
        """
        if key in ["enter", "i"]:
            self.close(None)


class CanDetailView(Pile):
    """
    Widget, which is being displayed, whenever a packet is being inspected.
    It is exchanged for the packetview.
    It lets one edit each packet field included in the selected packet.
    """

    def __init__(
        self,
        main_window,
        packet,  # type: GuiPacket,
        message_details,  # type: MessageDetailsData
    ):
        """
        :param packet: packet, which is currently selected and can be edited within this menu
        :type packet: Packet
        """

        statistic_analysis = LineBox(StatisticAnalysis(main_window, packet, message_details), "Statistics")
        all_pile = [("weight", 0.3, statistic_analysis), message_details.graph]
        super(CanDetailView, self).__init__(all_pile)


def open_menu(main_window, behavior, packet_in_focus):
    main_window.view_stack.append(main_window.body)

    message_details = MessageDetailsData(behavior.get_group(packet_in_focus.packet), behavior)
    message_details.set_detailed_message_information()
    message_details.create_graph()
    message_details.create_bit_correlation()

    main_window.body = CanDetailView(main_window, packet_in_focus, message_details)
