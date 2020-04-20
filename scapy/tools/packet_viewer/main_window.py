from typing import List
from urwid import Frame, Pile, AttrMap, Text, Button

from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer
from scapy.supersocket import SuperSocket
from scapy.tools.packet_viewer.columns_manager import ColumnsManager, PacketListColumn
from scapy.tools.packet_viewer.command_line_interface import CommandLineInterface
from scapy.tools.packet_viewer.details_view import DetailsView
from scapy.tools.packet_viewer.packet_list_view import PacketListView
from scapy.tools.packet_viewer.pop_ups import show_exit_pop_up, show_info_pop_up

PACKET_VIEW_INDEX = 0
STATUS_INDEX = 1
DETAIL_VIEW_INDEX = 2
DETAIL_CLOSE_BUTTON_INDEX = 3


class MainWindow(Frame):
    """
    Assembles all parts of the view.
    """
    def __init__(self, socket,  # type: SuperSocket
                 columns,  # type: List[PacketListColumn]
                 basecls,
                 **kwargs):

        basecls = basecls if basecls else getattr(socket, "basecls", Raw)

        cm = ColumnsManager(columns, basecls)

        self.packet_view = PacketListView(self, cm)

        self.main_loop = None

        self.details_view = DetailsView(self.close_details)

        super(MainWindow, self).__init__(
            body=Pile([self.packet_view,
                       ("pack", AttrMap(Text("Active"), "green"))]),
            header=AttrMap(Text("   " + cm.get_header_string()), "packet_view_header"),
            footer=CommandLineInterface(self)
        )

        self.sniffer = AsyncSniffer(
            opened_socket=socket, store=False, prn=self.packet_view.add_packet,
            lfilter=lambda p: isinstance(p, basecls), **kwargs
        )

        self.sniffer.start()
        self.sniffer_is_running = True

    def pause_packet_sniffer(self):
        if self.sniffer_is_running:
            self.sniffer.stop(False)

            self.body.contents[STATUS_INDEX] = (AttrMap(Text("Paused"), "red"), ("pack", None))
            self.sniffer_is_running = False
        else:
            show_info_pop_up(self.main_loop, "Can not pause sniffer: No active sniffer.")

    def continue_packet_sniffer(self):
        if not self.sniffer_is_running:
            self.sniffer.start()
            self.body.contents[STATUS_INDEX] = (AttrMap(Text("Active"), "green"), ("pack", None))
        else:
            show_info_pop_up(self.main_loop, "Can not start sniffer: Has already one active sniffer.")

    def quit(self):
        show_exit_pop_up(self)

    def show_details(
            self, packet  # type: Packet
    ):
        self.details_view.update(packet)

        dv_with_options = (self.details_view, ("weight", 0.3))
        if self.details_view.visible:
            self.body.contents[DETAIL_VIEW_INDEX] = dv_with_options
            self.body.contents[DETAIL_CLOSE_BUTTON_INDEX] = self.details_view.close_btn_widget
        else:
            self.body.contents.append(dv_with_options)
            self.body.contents.append(self.details_view.close_btn_widget)

        self.details_view.visible = True

    def close_details(
            self, _button=None  # type: Button
    ):
        if self.details_view.visible:
            self.body.contents.pop(DETAIL_CLOSE_BUTTON_INDEX)
            self.body.contents.pop(DETAIL_VIEW_INDEX)
            self.details_view.visible = False

    def update_details(
            self, packet  # type: Packet
    ):
        if self.details_view.visible:
            self.show_details(packet)

    def set_focus_footer(self):
        self.focus_position = "footer"
        self.footer.set_focused_state()

    # Keypress handling explained: http://urwid.org/manual/widgets.html
    def keypress(self, size, key):
        """
        Handles key-presses.
        """
        if key == ":":
            self.set_focus_footer()
            return
        if key == "esc":
            show_exit_pop_up(self)
            return

        super(MainWindow, self).keypress(size, key)
