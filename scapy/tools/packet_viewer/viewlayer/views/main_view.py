from itertools import count

from typing import Dict, Callable, List, Optional
from urwid import Frame, Pile, AttrMap, Text, Button

from scapy.sendrecv import AsyncSniffer
from scapy.supersocket import SuperSocket
from scapy.tools.packet_viewer.viewlayer.command_line_interface import CommandLineInterface
from scapy.tools.packet_viewer.viewlayer.packet import GuiPacket
from scapy.tools.packet_viewer.viewlayer.views.detail_view import DetailsView
from scapy.tools.packet_viewer.viewlayer.views.packet_list_view import PacketListView
from scapy.tools.packet_viewer.viewlayer.views.pop_ups import show_exit_pop_up, show_info_pop_up

PACKET_VIEW_INDEX = 0
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
        if width < 1:
            raise ValueError("Columns must have a width of at least 1.")

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
        basecls = getattr(socket, "basecls", basecls)

        c = count()
        self.columns = [MainWindowColumn("NO", 5, lambda p: next(c)), MainWindowColumn("TIME", 20, lambda p: p.time),
                        MainWindowColumn("LENGTH", 7, len)] + (columns or [])

        self.columns += [MainWindowColumn(field.name, 10, lambda p, name=field.name: p.fields[name])
                         for field in basecls.fields_desc]

        self.format_string = self._create_format_string(self.columns)

        self.packet_view = PacketListView(self, self.columns)

        self.main_loop = None

        self.details_view = DetailsView(False, self._close_details)

        super(MainWindow, self).__init__(
            body=Pile([self.packet_view,
                       ("pack", AttrMap(Text("Active"), "green"))]),
            header=AttrMap(Text("   " + self.get_header_string()), "packet_view_header"),
            footer=CommandLineInterface(self),
            focus_part="footer",
        )

        self.sniffer = AsyncSniffer(
            opened_socket=socket, store=False, prn=self.packet_view.add_packet,
            lfilter=lambda p: isinstance(p, basecls), **kwargs
        )
        self.sniffer.start()
        self.sniffer_is_running = True

    def pause_packet_sniffer(self):
        if self.sniffer_is_running:
            self.sniffer.stop()
            self.body.contents[STATUS_INDEX] = (AttrMap(Text("Paused"), "red"), ("pack", None))
            self.sniffer_is_running = False
        else:
            show_info_pop_up(self.main_window.main_loop, "Can not pause sniffer: No active sniffer.")

    def continue_packet_sniffer(self):
        if not self.sniffer_is_running:
            self.sniffer.start()
            self.body.contents[STATUS_INDEX] = (AttrMap(Text("Active"), "green"), ("pack", None))
        show_info_pop_up(self.main_window.main_loop, "Can not start sniffer: Has already one active sniffer.")

    def quit(self):
        show_exit_pop_up(self)

    def show_details(
            self, packet  # type: GuiPacket
    ):
        if self.details_view.visible:
            self.body.contents[DETAIL_VIEW_INDEX] = self.details_view.create_details_view(packet)
            self.body.contents[DETAIL_CLOSE_BUTTON_INDEX] = self.details_view.close_btn_widget
        else:
            self.body.contents.append(self.details_view.create_details_view(packet))
            self.body.contents.append(self.details_view.close_btn_widget)

        self.details_view.visible = True

    def _close_details(
            self, _button=None  # type: Button
    ):
        self.body.contents.pop(DETAIL_CLOSE_BUTTON_INDEX)
        self.body.contents.pop(DETAIL_VIEW_INDEX)
        self.details_view.visible = False

    def update_details(
            self, packet  # type: GuiPacket
    ):
        if self.details_view.visible:
            self.show_details(packet)

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
