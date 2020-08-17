# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import ast

from collections import OrderedDict
from typing import Union, Iterable, List, Type, Dict, Any, Optional

from urwid import Frame, Pile, AttrMap, Text, ExitMainLoop, connect_signal

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.sendrecv import AsyncSniffer
from scapy.supersocket import SuperSocket
from scapy.modules.packet_viewer.button_bar import ButtonBar, Action
from scapy.modules.packet_viewer.packet_list_view import PacketListView
from scapy.modules.packet_viewer.row_formatter import RowFormatter
from scapy.modules.packet_viewer.field_edit import FieldEdit
from scapy.modules.packet_viewer.details_view import DetailsView


class MainWindow(Frame):
    """
    Main Window of the packet_viewer, containing all view and connect signals
    between them.
    """
    PACKET_VIEW_INDEX = 0
    DETAILS_VIEW_INDEX = 1
    FILTER_INDEX = 2

    FILTER = "Filter"
    signals = ["question_popup", "info_popup", "input_popup"]

    def _create_buttons_for_footer(self):
        # type: () -> None
        """
        This function creates Actions for the buttons in the footer
        """
        # f1 is sometimes reserved by Terminals. Don't use it.
        if isinstance(self.source, SuperSocket):
            self.actions["f2"] = Action(["Re-Send"],
                                        [self.send_selected_packet])
            self.actions["f3"] = Action(
                ["Pause", "Continue"],
                [self.pause_packet_sniffer, self.continue_packet_sniffer])

        self.actions["f4"] = Action(["Quit"], [self.quit])
        self.actions["f5"] = Action([MainWindow.FILTER] * 2,
                                    [self.show_filter, self.hide_filter])
        self.actions["f6"] = Action(["Craft&Send"], [self.craft_packet])

    def _create_details_views(self, views):
        # type: (List[Type[DetailsView]]) -> None
        """
        This function creates and prepares all details views
        :param views: List of views which have to be created
        """
        # Key: details view; Value: is_visible
        self.details_views = dict()  # type: Dict[DetailsView, bool]
        self.view_actions = []
        for i, view_cls in enumerate(views):
            view = view_cls()
            action = Action([view.action_name.capitalize(),
                             view.action_name.upper(),
                             view.action_name.lower()],
                            [lambda v=view: self.show_view(v),
                             self.fullscreen_view,
                             self.hide_view])
            self.actions["f" + str(7 + i)] = action
            self.details_views[view] = False
            self.view_actions.append(action)
            connect_signal(view, "packet_modified", self.on_packet_changed)
            connect_signal(
                view, "notification",
                lambda _, message: self._emit("info_popup", message))

    def _create_filter(self):
        # type: () -> None
        """
        This function creates and connects the filter box
        """
        filter_edit = FieldEdit(MainWindow.FILTER + ": ")
        connect_signal(filter_edit, "apply",
                       lambda _sender, text: self.filter_changed(text))

        self.filter_box = (AttrMap(filter_edit, "row_focused"), ("pack", None))

    def _setup_source(self, kwargs_for_sniff):
        # type: (Dict[str, Any]) -> None
        """
        This function either starts a AsyncSniffer for the given socket or
        inserts all Packets from a source list into the packet_view
        :param kwargs_for_sniff: Arguments for sniff
        """
        if isinstance(self.source, SuperSocket):
            self.sniffer = AsyncSniffer(
                opened_socket=self.source, store=False,
                prn=self.packet_view.add_packet,
                **kwargs_for_sniff
            )
            self.sniffer.start()
        elif hasattr(self.source, "__iter__"):
            self.sniffer = None
            for p in self.source:
                self.packet_view.add_packet(p)
        else:
            raise Scapy_Exception("Provide list of packets or Socket")

    def __init__(self, source, row_formatter, views, **kwargs_for_sniff):
        # type: (Union[SuperSocket, Iterable[Packet]], RowFormatter, List[Type[DetailsView]], Optional[Dict[str, Any]]) -> None  # noqa: E501

        self.packet_view = PacketListView(row_formatter)
        connect_signal(
            self.packet_view.body, "modified",
            self.on_focused_packet_changed)

        self.source = source
        self.actions = OrderedDict()  # type: OrderedDict[str, Action]

        self._create_buttons_for_footer()
        self._create_details_views(views)
        self._create_filter()
        self._setup_source(kwargs_for_sniff)

        super(MainWindow, self).__init__(
            header=AttrMap(Text(u"    " + row_formatter.get_header_string(),
                                wrap="ellipsis"),
                           "header"),
            body=Pile([self.packet_view]),
            # OrderedDict to ensure the order of the buttons
            # are exactly as in the dictionary.
            footer=ButtonBar(self.actions)
        )

    def focus_packet_view(self):
        # type: () -> None
        self.focus_position = "body"
        self.body.focus_item = self.packet_view

    @property
    def focused_packet(self):
        # type: () -> Packet
        if self.packet_view.focus:
            return self.packet_view.focus.base_widget.tag

    @property
    def selected_packets(self):
        # type: () -> PacketList
        return PacketList([cb.base_widget.tag for cb in self.packet_view.body
                           if cb.base_widget.state is True],
                          name="selected")

    @property
    def all_packets(self):
        # type: () -> PacketList
        return PacketList(self.packet_view.packets, name="all")

    def pause_packet_sniffer(self):
        # type: () -> None
        try:
            self.sniffer.stop()
        except (Scapy_Exception, AttributeError):
            pass

    def continue_packet_sniffer(self):
        # type: () -> None
        try:
            self.sniffer.start()
        except (Scapy_Exception, AttributeError):
            pass

    def send_selected_packet(self):
        # type: () -> None
        if self.focused_packet:
            self.send_packet(self.focused_packet)

    def send_packet(self, pkt):
        # type: (Packet) -> None
        if isinstance(self.source, SuperSocket):
            self.source.send(pkt)

    def text_to_packet(self, text):
        # type: (str) -> bool
        """
        Creates a packet from a string and sends this packet, on success.
        Shows a info_popup on error
        :param text: String that describes a Scapy Packet
        """
        try:
            exec(compile(ast.parse("locals()['pkt_parse_result'] = " + text),
                         filename="", mode="exec"))
            pkt = locals()['pkt_parse_result']
            self.send_packet(pkt)
            return True
        except (SyntaxError, AttributeError, Scapy_Exception, TypeError) as e:
            self._emit("info_popup", str(e))
            return False

    def craft_packet(self):
        # type: () -> None
        """
        Show input_popup to enter the description of a Scapy Packet
        """
        self._emit(
            "input_popup", "Packet: ",
            self.focused_packet.command() if self.focused_packet else "",
            "SEND", self.text_to_packet)

    def quit(self):
        # type: () -> None
        self._emit("question_popup", "Really quit?", self._on_exit)

    def _on_exit(self, _sender=None):
        try:
            self.sniffer.stop()
        except (Scapy_Exception, AttributeError):
            pass
        finally:
            raise ExitMainLoop()

    @property
    def visible_view(self):
        # type: () -> Optional[DetailsView]
        for view, visible in self.details_views.items():
            if visible:
                return view
        return None

    @staticmethod
    def evaluate_filter(p, filter_text):
        # type: (Packet, str) -> bool
        try:
            exec(compile(ast.parse(
                "locals()['filter_eval_result'] = " + filter_text),
                filename="",
                mode="exec"))
            return locals()['filter_eval_result']
        except AttributeError:
            return False

    def filter_changed(self, new_filter):
        # type: (str) -> None
        if new_filter == "":
            # deselect all packets
            for cb in self.packet_view.body:
                cb.base_widget.state = False
            return

        try:
            for cb in self.packet_view.body:
                pkt = cb.base_widget.tag
                cb.base_widget.state = \
                    self.evaluate_filter(pkt, new_filter)
        except NameError:
            self._emit(
                "info_popup",
                "Always use 'p' for your expression.\n"
                "Example: p.attr == 'something'")
        except (SyntaxError, Scapy_Exception, TypeError) as e:
            self._emit("info_popup", str(e))

    def show_filter(self):
        # type: () -> None
        self.body.contents.insert(MainWindow.FILTER_INDEX, self.filter_box)
        self.focus_position = "body"
        self.body.focus_item = self.filter_box[0]

    def hide_filter(self):
        # type: () -> None
        self.body.contents.pop(self.body.contents.index(self.filter_box))
        self.filter_changed("")

    def show_view(self, toggled_view):
        # type: (DetailsView) -> None
        if self.visible_view is not None:
            # Reset the states of the actions to initial state
            for action in self.view_actions:
                action.reset()
            # Show the new states also in the buttons
            self.footer.refresh()
            self.hide_view()
        # Ensure it shows the correct data
        if self.focused_packet is not None:
            toggled_view.update_packets(
                self.focused_packet, self.packet_view.packets)
        self.body.contents.insert(
            MainWindow.DETAILS_VIEW_INDEX, (toggled_view, ("weight", 0.3)))
        self.details_views[toggled_view] = True
        self.focus_packet_view()

    def hide_view(self):
        # type: () -> None
        self.body.contents.pop(MainWindow.DETAILS_VIEW_INDEX)
        if self.visible_view is not None:
            self.details_views[self.visible_view] = False

    def fullscreen_view(self):
        # type: () -> None
        self.body.contents[MainWindow.DETAILS_VIEW_INDEX] = \
            (self.visible_view, ("weight", 3))

    # Keypress handling explained: http://urwid.org/manual/widgets.html
    def keypress(self, size, key):
        if key.startswith("f") and len(key) >= 2:
            # Redirect Fxx keypresses to footer even if footer is not focused
            return self.footer.keypress(size, key)

        return super(MainWindow, self).keypress(size, key)

    def on_focused_packet_changed(self):
        # type: () -> None
        # Only update if visible for performance
        if self.visible_view:
            self.visible_view.update_packets(
                self.focused_packet, self.packet_view.packets)

    def on_packet_changed(self, _sender=None):
        self.focus_packet_view()
        self.packet_view.update_selected_packet()
