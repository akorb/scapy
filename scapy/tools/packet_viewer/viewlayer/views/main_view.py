from typing import List

from urwid import Frame, Widget, Pile, AttrMap, Text, Filler, LineBox, Columns

from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior
from scapy.tools.packet_viewer.datalayer.behaviors.all import DIC_SOCKET_INFORMATION
from scapy.tools.packet_viewer.viewlayer.command_line_interface import CommandLineInterface
from scapy.tools.packet_viewer.viewlayer.packet import GuiPacket
from scapy.tools.packet_viewer.viewlayer.views.menu_view import CanDetailView
from scapy.tools.packet_viewer.viewlayer.views.packet_list_view import PacketListView
from scapy.tools.packet_viewer.viewlayer.views.pop_ups import show_exit_pop_up
from scapy.utils import hexdump


class MainWindow(Frame):
    """
    Assembles all parts of the view.
    """

    def __init__(self, socket, **kwargs):
        socket_info = DIC_SOCKET_INFORMATION.get(socket.basecls, DefaultBehavior)(socket)
        super().__init__(
            body=Pile([PacketListView(self, socket_info)]),
            header=AttrMap(Text("   " + socket_info.get_header()), "packet_view_header"),
            footer=CommandLineInterface(self),
            focus_part="footer",
        )

        self.main_loop = None
        self.view_stack: List[Widget] = []

        self.sniffer = AsyncSniffer(opened_socket=socket, store=False, prn=self.add_packet, **kwargs)
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

    def show_details(self, packet: GuiPacket, message_details):
        # detail_view = LineBox(CanDetailView(self, packet, message_details))
        # widget, (t, w) = self.body.contents[0]
        # self.body.contents[0] = (widget, (t, 0.5))
        show_text = packet.packet.show(dump=True)

        show_text = Text(show_text)
        hexdump_text = Text(hexdump(packet.packet, dump=True))

        col = Columns([('pack', show_text), hexdump_text], dividechars=4)
        linebox = LineBox(Filler(col, 'top'))

        new_widget = (linebox, ('weight', 0.3))

        # must give a box widget
        # weight 1.0 is fine, since it automatically divides it evenly between all widgets if all of its weights are 1.0
        if len(self.body.contents) == 2:
            self.body.contents[1] = new_widget
        else:
            self.body.contents.append(new_widget)

    def add_packet(self, packet):
        """
        Adds a packet to the packet_view_list.

        :param packet: packet sniffed on the interface
        :type packet: Packet
        :return: None
        """

        packet_list_view, _ = self.body.contents[0]
        packet_list_view.add_packet(packet)
        self.main_loop.draw_screen()

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
