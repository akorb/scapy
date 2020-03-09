from threading import RLock
from typing import List

from urwid import Frame, Widget, Pile, AttrMap, Text

from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior
from scapy.tools.packet_viewer.datalayer.behaviors.all import DIC_SOCKET_INFORMATION
from scapy.tools.packet_viewer.techlayer.sniffer import Sniffer
from scapy.tools.packet_viewer.viewlayer.command_line_interface import CommandLineInterface
from scapy.tools.packet_viewer.viewlayer.views.packet_list_view import PacketListView
from scapy.tools.packet_viewer.viewlayer.views.pop_ups import show_exit_pop_up


DRAW_LOCK: RLock = RLock()


class MainWindow(Frame):
    """
    Assembles all parts of the view.
    """

    def __init__(self, socket, **kwargs):
        socket_info = DIC_SOCKET_INFORMATION.get(socket.basecls, DefaultBehavior)(socket)
        super().__init__(
            body=Pile([PacketListView(self, socket_info, DRAW_LOCK)]),
            header=AttrMap(Text("   " + socket_info.get_header()), "packet_view_header"),
            footer=CommandLineInterface(self),
            focus_part="footer",
        )

        self.main_loop = None
        self.view_stack: List[Widget] = []

        self.sniffer = Sniffer(self, socket, **kwargs)
        self.sniffer.start()

    def pause_packet_sniffer(self):
        self.sniffer.stop()
        # TODO: Add status label at the bottom-right corner like in vim

    def continue_packet_sniffer(self):
        self.sniffer.start()
        # TODO: Add status label at the bottom-right corner like in vim

    def quit(self):
        self.sniffer.stop()
        show_exit_pop_up(self)
        # TODO: Popup really required?

    def set_focus_footer(self):
        self.focus_position = "footer"
        self.footer.set_caption(":")

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
