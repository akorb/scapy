# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import re

from platform import platform
from urwid import MainLoop, connect_signal, WidgetMeta, raw_display
from typing import Optional, Union, Iterable, List, Tuple, Callable, Dict, \
    Any, Type

from scapy.config import conf
from scapy.packet import Packet_metaclass, Packet
from scapy.supersocket import SuperSocket
from scapy.themes import BlackAndWhite
from scapy.plist import PacketList

from scapy.modules.packet_viewer.show_view import ShowView
from scapy.modules.packet_viewer.main_window import MainWindow
from scapy.modules.packet_viewer.row_formatter import RowFormatter
from scapy.modules.packet_viewer.pop_ups import show_question_pop_up, \
    show_info_pop_up, show_input_pop_up

import scapy.modules.packet_viewer.column_configuration  # noqa: F401


class ScreenWSL(raw_display.Screen):
    def write(self, data):
        # type: (str) -> None
        """
        Write function for custom WSL screen. This replace urwid's SI/SO,
        which produce artifacts under WSL
        :param data: Some data to write to the raw_display.Screen
        """
        if "microsoft" in platform().lower():
            data = re.sub("[\x0e\x0f]", "", data)
        super(ScreenWSL, self).write(data)


class Viewer(object):
    """
    A packet viewer for Scapy. Based on urwid this class can visualize packets.
    This viewer is extendable and customizable.
    The following configurations are used internally:
        conf.contribs["packet_viewer_custom_views"]
        conf.contribs["packet_viewer_columns"]

    Customize views:
        Derive a custom view from DetailsView and implement
        the desired behaviour. Add your view as list to the configuration.
        conf.contribs["packet_viewer_custom_views"] = [myCustomView]

        CustomViews can also be given to the Viewer directly:
        ```Viewer(source, views=[myCustomView])```

    Customize columns:
        The configuration of conf.contribs["packet_viewer_columns"] contains
        a dictionary where the key is the basecls of a packet. This allows
        you to customize the packet_viewer columns dependent on a basecls.
        A column description is defined as a list of tuples where every
        tuple defines a column.
        The definition of a column consists of a string for the name, an int
        for the column width and a function for the determination of
        the content. Example:
        ```
        src_col = ("SRC", 15, lambda p: p.src)
        dst_col = ("DST", 15, lambda p: p.dst)
        # assign column definitions to IP packets
        conf.contribs["packet_viewer_columns"][IP] = [src_col, dst_col]
        ```
        Now the packet_viewer shows the default columns, followed by
        this custom columns if a basecls is provided.
        A identical configuration can be given to the constructor to customize
        the columns even more. Example:
        ```
        Viewer(source, columns=[src_col, dst_col])
        ```
        Attention: This requires that every packet from the source has the
        attributes `src` and `dst`.
    """

    def __init__(self, source, columns, basecls, views,
                 globals_dict, **kwargs_for_sniff):
        # type: (Union[SuperSocket, Iterable[Packet]], Optional[List[Tuple[str, int, Callable[[Packet], str]]]], Optional[Packet_metaclass], Optional[List[WidgetMeta]], Optional[Dict], Optional[Dict[str, Any]]) -> None  # noqa: E501
        """
        Initialization of a Viewer class. Customization and basecls filtering
        can be chosen through the arguments
        :param source: Any list of Packets or a Socket.
        :param columns: A list of column configuration tuples.
        :param basecls: A basecls for basecls filtering. If this argument is
                        provided, only packets from this instance are shown.
                        If a basecls is provided. The Viewer will automatically
                        read basecls specific column configuration from
                        `conf.contribs["packet_viewer_columns"]`.
        :param views: Custom or additional views.
        :param kwargs_for_sniff: Arguments for sniff, if source is a socket.
        """
        self.palette = [
            ("header", "black", "dark green"),
            ("row_focused", "black", "dark cyan"),
            ("green", "black", "dark green"),
            ("red", "white", "dark red"),
            ("default_bold", "bold", ""),
        ]

        if views is None:
            self.views = [ShowView]
            self.views += conf.contribs.get("packet_viewer_custom_views", [])

        for view in self.views:
            self.palette += getattr(view, "palette", [])

        self.source = source
        self.globals_dict = globals_dict
        self.kwargs_for_sniff = kwargs_for_sniff
        self.formatter = RowFormatter(columns, basecls)
        self.main_window = None   # type: Optional[MainWindow]
        self.loop = None          # type: Optional[MainLoop]

    def _connect_signals(self):
        # type: () -> None
        """
        Internal function to connect signals from MainWindow to PopUps
        """
        if self.main_window is None:
            return

        connect_signal(
            self.main_window, "question_popup",
            lambda _, msg, cb: show_question_pop_up(self.loop, msg, cb))

        connect_signal(
            self.main_window, "input_popup",
            lambda _, caption, initial, button_text, callback: show_input_pop_up(self.loop, caption, initial, button_text, callback))  # noqa: E501

        connect_signal(
            self.main_window, "info_popup",
            lambda _, info: show_info_pop_up(self.loop, info))

        connect_signal(
            self.main_window.packet_view, "packets_modified",
            self._update_screen)

    def run(self):
        # type: () -> Tuple[PacketList, PacketList]
        """
        Start Viewer
        :return: Tuple of two PacketLists. First list contains all selected
                 Packets. Second list contains all Packets
        """
        cf = conf.color_theme
        conf.color_theme = BlackAndWhite()
        self.main_window = MainWindow(self.source, self.formatter, self.views,
                                      self.globals_dict,
                                      **self.kwargs_for_sniff)

        self.loop = MainLoop(self.main_window, palette=self.palette,
                             screen=ScreenWSL())
        # noinspection PyBroadException
        try:
            self._connect_signals()
            self.loop.run()
        except Exception:
            pass
        finally:
            conf.color_theme = cf

        return self.main_window.selected_packets, self.main_window.all_packets

    def _update_screen(self, *_args):
        # type: (Optional[Any]) -> None
        """
        Internal function to update screen. Used by signals that get emitted on
        modifications of internal contents
        :param _args: Not used. Required by urwid signal
        """
        if self.loop is None:
            return

        try:
            self.loop.draw_screen()
        except (AssertionError, AttributeError):
            pass


def viewer(source, columns=None, basecls=None, views=None, globals_dict=None,
           **kwargs_for_sniff):
    # type: (Union[SuperSocket, Iterable[Packet]], Optional[List[Tuple[str, int, Callable[[Packet], str]]]], Optional[Type[Packet]], Optional[List[WidgetMeta]], Optional[Dict], Optional[Dict[str, Any]]) -> Tuple[PacketList, PacketList]  # noqa: E501
    """
    Convenience function for Viewer
    :param source: Socket or list of Packets
    :param columns: List of column configuration tuples
    :param basecls: Packet_metaclass for basecls filtering and
                    column configuration determination
    :param views: List of custom views
    :param globals_dict: Necessary for crafting packets in this tool,
                         since this dictionary contains the imported
                         Packet classes.
    :param kwargs_for_sniff: Parameters forwarded to sniff
                             if source is a socket
    :return: Tuple of two PacketLists. First list contains all selected
             Packets. Second list contains all Packets
    """
    v = Viewer(source, columns, basecls, views, globals_dict,
               **kwargs_for_sniff)
    return v.run()
