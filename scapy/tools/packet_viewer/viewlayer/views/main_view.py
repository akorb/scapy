from typing import List, Dict
from urwid import Frame, Widget, Pile, AttrMap, Text, Filler, LineBox, Columns, Button

from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.tools.packet_viewer.viewlayer.command_line_interface import CommandLineInterface
from scapy.tools.packet_viewer.viewlayer.packet import GuiPacket
from scapy.tools.packet_viewer.viewlayer.views.packet_list_view import PacketListView
from scapy.tools.packet_viewer.viewlayer.views.pop_ups import show_exit_pop_up
from scapy.utils import hexdump


class MainWindow(Frame):
    """
    Assembles all parts of the view.
    """

    def get_header(self):
        # type: (...) -> str
        cols = dict()  # type: Dict[str, str]
        for (name, _, _) in self.columns:
            cols[name] = name.upper()

        return self.format_string.format(**cols)

    @staticmethod
    def _create_format_string(columns):
        format_string = ""
        for (name, length, _) in columns:
            format_string += "{" + name + ":<" + str(length) + "}"
        return format_string

    def __init__(self, socket, columns, _get_group, _get_data, basecls, **kwargs):
        self.basecls = socket.basecls if hasattr(socket, "basecls") else basecls

        self.columns = [("TIME", 20, lambda p: p.time), ("LENGTH", 7, lambda p: len(p))]

        if columns:
            self.columns += columns

        for field in self.basecls.fields_desc:
            col = (field.name, 10, lambda p, name=field.name: p.fields[name])
            self.columns.append(col)

        self.format_string = self._create_format_string(self.columns)

        super(MainWindow, self).__init__(
            body=Pile([PacketListView(self, self.columns)]),
            header=AttrMap(Text("   " + self.get_header()), "packet_view_header"),
            footer=CommandLineInterface(self),
            focus_part="footer",
        )

        self.main_loop = None
        self.view_stack = []  # type: List[Widget]

        self.sniffer = AsyncSniffer(
            opened_socket=socket, store=False, prn=self.add_packet, lfilter=lambda p: isinstance(p, basecls), **kwargs
        )
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

    def close_details(
        self, _button=None  # type: Button
    ):
        self.body.contents.pop(2)
        self.body.contents.pop(1)

    def show_details(
        self, packet  # type: GuiPacket
    ):

        close_btn = AttrMap(Button("Close details (press this button or click c)", self.close_details), "green")
        close_btn_widget = (close_btn, ("pack", None))

        show_text = packet.packet.show(dump=True)

        show_text = Text(show_text)
        hexdump_text = Text(hexdump(packet.packet, dump=True))

        col = Columns([("pack", show_text), hexdump_text], dividechars=4)
        linebox = LineBox(Filler(col, "top"))

        new_widget = (linebox, ("weight", 0.3))

        # must give a box widget
        # weight 1.0 is fine, since it automatically divides it evenly between all widgets if all of its weights are 1.0
        if len(self.body.contents) >= 2:
            self.body.contents[1] = new_widget
        else:
            self.body.contents.append(new_widget)
            self.body.contents.append(close_btn_widget)

    def update_details(
        self, packet  # type: GuiPacket
    ):
        if len(self.body.contents) >= 2:
            self.show_details(packet)

    def add_packet(self, packet):
        """
        Adds a packet to the packet_view_list.

        :param packet: packet sniffed on the interface
        :type packet: Packet
        :return: None
        """

        packet_list_view, _ = self.body.contents[0]
        packet_list_view.add_packet(packet)
        if self.main_loop:
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
