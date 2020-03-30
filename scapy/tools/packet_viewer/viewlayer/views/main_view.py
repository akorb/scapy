from itertools import count

from typing import Dict, Callable, List, Optional
from urwid import Frame, Pile, AttrMap, Text, Filler, LineBox, Columns, Button

from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.supersocket import SuperSocket
from scapy.tools.packet_viewer.viewlayer.command_line_interface import CommandLineInterface
from scapy.tools.packet_viewer.viewlayer.packet import GuiPacket
from scapy.tools.packet_viewer.viewlayer.views.packet_list_view import PacketListView
from scapy.tools.packet_viewer.viewlayer.views.pop_ups import show_exit_pop_up
from scapy.utils import hexdump

STATUS_INDEX = 1
DETAIL_VIEW_INDEX = 2
DETAIL_CLOSE_BUTTON_INDEX = 3


class MainWindowColumn:
    """
    Class to define size and content of a column in main view
    """

    def __init__(self, name,  # type: str
                 width,  # type: int
                 func,  # type: Callable
                 ):
        """
        :param name: String that is used as Header of the column and reference
        :param width: Width of the column
        :param func: A callable function that should take Packet as input and return what will be displayed in the column
        """
        self.name = name
        self.width = width
        self.func = func


class MainWindow(Frame):
    """
    Assembles all parts of the view.
    """

    def get_header_string(self):
        # type: (...) -> str
        cols = dict()  # type: Dict[str, str]
        for column in self.columns:
            cols[column.name] = column.name.upper()

        return self.format_string.format(**cols)

    @staticmethod
    def _create_format_string(columns  # type: List[MainWindowColumn]
                              ):
        format_string = ""
        for column in columns:
            format_string += "{" + column.name + ":<" + str(column.width) + "}"
        return format_string

    def __init__(self, socket,  # type: SuperSocket
                 columns,  # type: Optional[List[MainWindowColumn]]
                 _get_group, _get_bytes_for_analysis, basecls, **kwargs):
        basecls = socket.basecls if hasattr(socket, "basecls") else basecls

        c = count()
        self.columns = [MainWindowColumn("NO", 5, lambda p: next(c)), MainWindowColumn("TIME", 20, lambda p: p.time),
                        MainWindowColumn("LENGTH", 7, lambda p: len(p))]

        if columns:
            self.columns += columns

        for field in basecls.fields_desc:
            col = MainWindowColumn(field.name, 10, lambda p, name=field.name: p.fields[name])
            self.columns.append(col)

        self.format_string = self._create_format_string(self.columns)

        super(MainWindow, self).__init__(
            body=Pile([PacketListView(self, self.columns),
                       ("pack", AttrMap(Text("Active"), "green"))]),
            header=AttrMap(Text("   " + self.get_header_string()), "packet_view_header"),
            footer=CommandLineInterface(self),
            focus_part="footer",
        )

        self.main_loop = None

        self.sniffer = AsyncSniffer(
            opened_socket=socket, store=False, prn=self.add_packet, lfilter=lambda p: isinstance(p, basecls), **kwargs
        )
        self.sniffer.start()

    def pause_packet_sniffer(self):
        self.sniffer.stop()
        self.body.contents[STATUS_INDEX] = (AttrMap(Text("Paused"), "red"), ("pack", None))

    def continue_packet_sniffer(self):
        self.sniffer.start()
        self.body.contents[STATUS_INDEX] = (AttrMap(Text("Active"), "green"), ("pack", None))

    def quit(self):
        show_exit_pop_up(self)

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

        close_btn = AttrMap(Button("Close details (press this button or click c)", self.close_details), "green")
        close_btn_widget = (close_btn, ("pack", None))

        show_text = packet.packet.show(dump=True)

        show_text = Text(show_text)
        hexdump_text = Text(hexdump(packet.packet, dump=True), align="right")

        col = Columns([("pack", show_text), hexdump_text], dividechars=4)
        linebox = LineBox(Filler(col, "top"))

        new_widget = (linebox, ("weight", 0.3))

        # must give a box widget
        # weight 1.0 is fine, since it automatically divides it evenly between all widgets if all of its weights are 1.0
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
