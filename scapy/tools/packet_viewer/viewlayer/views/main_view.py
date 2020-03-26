from typing import List, Dict
from urwid import Frame, Widget, Pile, AttrMap, Text, Filler, LineBox, Columns, Button

from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer
from scapy.utils import hexdump

from scapy.tools.packet_viewer.viewlayer.command_line_interface import CommandLineInterface
from scapy.tools.packet_viewer.viewlayer.packet import GuiPacket
from scapy.tools.packet_viewer.viewlayer.views.packet_list_view import PacketListView
from scapy.tools.packet_viewer.viewlayer.views.pop_ups import show_exit_pop_up

STATUS_INDEX = 1
DETAIL_VIEW_INDEX = 2
DETAIL_CLOSE_BUTTON_INDEX = 3


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

    def __init__(self, socket, columns=None, _get_group=len,
                 _get_data=lambda p: bytearray(bytes(p)),
                 basecls=Raw, **kwargs):
        self.basecls = getattr(socket, "basecls", basecls)

        self.columns = [("TIME", 20, lambda p: p.time), ("LENGTH", 7, len)] + \
                       (columns or [])

        self.columns += [(field.name, 10,
                          lambda p, name=field.name: p.fields[name])
                         for field in self.basecls.fields_desc]

        self.format_string = self._create_format_string(self.columns)

        super(MainWindow, self).__init__(
            body=Pile([PacketListView(self, self.columns)]),
            header=AttrMap(
                Text("   " + self.get_header()), "packet_view_header"),
            footer=CommandLineInterface(self),
            focus_part="footer",
        )

        self.main_loop = None
        self.view_stack = []  # type: List[Widget]

        self.sniffer = AsyncSniffer(
            opened_socket=socket, store=False, prn=self.add_packet,
            lfilter=lambda p: isinstance(p, basecls), **kwargs
        )
        self.sniffer.start()
        self.body.contents.append((AttrMap(Text("Active"), "green"),
                                   ("pack", None)))

    def pause_packet_sniffer(self):
        self.sniffer.stop()
        self.body.contents[STATUS_INDEX] = (AttrMap(Text("Paused"), "red"),
                                            ("pack", None))

    def continue_packet_sniffer(self):
        self.sniffer.start()
        self.body.contents[STATUS_INDEX] = (AttrMap(Text("Active"), "green"),
                                            ("pack", None))

    def quit(self):
        self.sniffer.stop()
        show_exit_pop_up(self)
        # TODO: Popup really required?

    def close_details(
        self, _button=None  # type: Button
    ):
        # if it is not four, the detail window is not shown yet
        if len(self.body.contents) == 4:
            self.body.contents.pop(DETAIL_CLOSE_BUTTON_INDEX)
            self.body.contents.pop(DETAIL_VIEW_INDEX)

    def show_details(
        self, packet  # type: GuiPacket
    ):

        close_btn = AttrMap(
            Button("Close details (press this button or click c)",
                   self.close_details), "green")
        close_btn_widget = (close_btn, ("pack", None))

        show_text = packet.packet.show(dump=True)

        show_text = Text(show_text)
        hexdump_text = Text(hexdump(packet.packet, dump=True))

        col = Columns([("pack", show_text), hexdump_text], dividechars=4)
        linebox = LineBox(Filler(col, "top"))

        new_widget = (linebox, ("weight", 0.3))

        # must give a box widget
        # weight 1.0 is fine, since it automatically divides it
        # evenly between all widgets if all of its weights are 1.0
        if len(self.body.contents) >= DETAIL_CLOSE_BUTTON_INDEX:
            self.body.contents[DETAIL_VIEW_INDEX] = new_widget
        else:
            self.body.contents.append(new_widget)
            self.body.contents.append(close_btn_widget)

    def update_details(
        self, packet  # type: GuiPacket
    ):
        if len(self.body.contents) >= DETAIL_CLOSE_BUTTON_INDEX:
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
