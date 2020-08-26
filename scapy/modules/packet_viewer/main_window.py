# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import ast

from collections import OrderedDict
from typing import Union, Iterable, List, Type, Dict, Any, Optional, Tuple, \
    Callable

from urwid import Frame, Pile, AttrMap, Text, ExitMainLoop, connect_signal

from scapy.base_classes import Packet_metaclass
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
    SEND_INDEX = 3

    FILTER = "Filter"
    SEND = "Send"
    signals = ["question_popup", "info_popup"]

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
                                    [lambda: self.show_bottom_line(
                                        MainWindow.FILTER_INDEX,
                                        self.filter_box),
                                     lambda: self.hide_bottom_line(
                                         self.filter_box)])

        if self.globals_dict is not None:
            self.actions["f6"] = Action(["Craft&Send"] * 2,
                                        [lambda: self.show_bottom_line(
                                            MainWindow.FILTER_INDEX,
                                            self.send_box,
                                            self.focused_packet.command()
                                            if self.focused_packet else ""),
                                         lambda: self.hide_bottom_line(
                                             self.send_box)])

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

    @staticmethod
    def _create_bottom_input(caption, callback):
        # type: (str, Callable) -> Tuple[AttrMap, Tuple]
        """
        This function creates an object for the bottom line.
        :param callback: Called if enter pressed.
        Should take only two parameters.
        `self` and a string containing the current text.
        """
        edit = FieldEdit(caption + ": ")
        connect_signal(edit, "apply",
                       lambda _sender, text: callback(text))

        return AttrMap(edit, "row_focused"), ("pack", None)

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

    def __init__(self, source, row_formatter, views, globals_dict,
                 **kwargs_for_sniff):
        # type: (Union[SuperSocket, Iterable[Packet]], RowFormatter, List[Type[DetailsView]], Optional[Dict], Optional[Dict[str, Any]]) -> None  # noqa: E501

        self.packet_view = PacketListView(row_formatter)
        connect_signal(
            self.packet_view.body, "modified",
            self.on_focused_packet_changed)

        self.globals_dict = globals_dict
        self.source = source

        # OrderedDict to ensure the order of the buttons
        # are exactly as in the dictionary.
        self.actions = OrderedDict()  # type: OrderedDict[str, Action]

        self._create_buttons_for_footer()
        self._create_details_views(views)

        self.filter_box = self._create_bottom_input(MainWindow.FILTER,
                                                    self.filter_changed)
        self.send_box = self._create_bottom_input(MainWindow.SEND,
                                                  self.text_to_packet)
        self._setup_source(kwargs_for_sniff)

        from six import PY2
        super(MainWindow, self).__init__(
            # urwid crashes with Py2 and ellipsis
            # Fixed with https://github.com/urwid/urwid/pull/427
            # Todo: Revert fallback to "clip" for PY2 when
            # new urwid version is released.
            # Current 2.1.1
            header=AttrMap(Text(u"    " + row_formatter.get_header_string(),
                                wrap="clip" if PY2 else "ellipsis"),
                           "header"),
            body=Pile([self.packet_view]),
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

    @staticmethod
    def is_valid_packet(text, globals_dict):
        # eval enforces only one expression
        try:
            tree = ast.parse(text, mode="eval")
        except SyntaxError:
            return False, []
        gen = ast.walk(tree)
        required_classes = []
        from six import PY3
        for node in gen:
            # Set parent to use it again later (probably next iterations)
            for child in ast.iter_child_nodes(node):
                child.parent = node

            # Allowed elements
            if isinstance(node, (ast.Load, ast.BinOp, ast.Call, ast.operator,
                                 ast.Expression, ast.List)):
                continue

            # Python >= 3.8 (For future usage)
            # isinstance(node, ast.Constant)
            if isinstance(node, (ast.keyword, ast.Num, ast.Str)) or \
                    (PY3 and isinstance(node, ast.Bytes)):
                continue

            if isinstance(node, ast.Name):
                # A name must be a child of a call
                # Allowed: CAN()
                # Disallowed: CAN
                if not isinstance(node.parent, ast.Call):
                    return False, []

                # Use empty dictionary if builtins have been overwritten
                builtin = getattr(globals_dict["__builtins__"], "__dict__", {})
                t = globals_dict.get(node.id) or builtin.get(node.id)
                # Must be of type Packet_metaclass
                if not isinstance(t, Packet_metaclass):
                    return False, []
                required_classes.append(t)
                continue

            return False, []

        return True, required_classes

    def text_to_packet(self, text):
        # type: (str) -> bool
        """
        Creates a packet from a string and sends this packet, on success.
        Shows a info_popup on error
        :param text: String that describes a Scapy Packet
        """
        try:
            valid, required_classes = \
                MainWindow.is_valid_packet(text, self.globals_dict)
            if valid:
                # Create own minimized global symbol table
                # to improve security
                g = {c.__name__: c for c in required_classes}

                # From https://docs.python.org/3/library/functions.html#eval
                # If the globals dictionary is present and does not contain
                # a value for the key __builtins__, a reference to
                # the dictionary of the built-in module builtins is inserted
                # under that key before expression is parsed.
                #
                # We don't want any builtins to be executed.
                g["__builtins__"] = {}
                pkt = eval(text, g)
                self.send_packet(pkt)
            else:
                self._emit("info_popup", "Only simple values allowed.")

            return True
        except (SyntaxError, AttributeError, Scapy_Exception, TypeError,
                NameError) as e:
            self._emit("info_popup", str(e))
            return False

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

    def filter_changed(self, new_filter):
        # type: (str) -> None
        # strip avoids some crashes
        new_filter = new_filter.strip()
        if new_filter == "":
            # deselect all packets
            for cb in self.packet_view.body:
                cb.base_widget.state = False
            return

        try:
            compiled_code = compile(new_filter, filename="", mode="eval")
            for cb in self.packet_view.body:
                p = cb.base_widget.tag
                # See text_to_packet() for some explanations
                g = {"p": p, "__builtins__": {}}
                matches = bool(eval(compiled_code, g))
                cb.base_widget.state = matches
        except NameError:
            self._emit(
                "info_popup",
                "Always use 'p' for your expression.\n"
                "Example: p.attr == 'something'")
        except (SyntaxError, Scapy_Exception, TypeError) as e:
            self._emit("info_popup", str(e))
        except AttributeError as e:
            self._emit("info_popup", "Attribute " + str(e) + " unknown.")

    def show_bottom_line(self, index, widget_tuple, initial=""):
        # type: (int, Tuple, Optional[str]) -> None
        widget_tuple[0].base_widget.edit_text = initial
        self.body.contents.insert(index, widget_tuple)
        self.focus_position = "body"
        self.body.focus_item = widget_tuple[0]

    def hide_bottom_line(self, widget_tuple):
        # type: (Tuple) -> None
        self.body.contents.pop(self.body.contents.index(widget_tuple))

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
        if key.startswith("f") and 2 <= len(key) <= 3:
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
