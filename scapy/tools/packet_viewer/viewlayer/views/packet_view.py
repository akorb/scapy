from threading import RLock
from typing import Union

from urwid import Frame, AttrMap, Text

from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior
from scapy.tools.packet_viewer.viewlayer.views.packet_list_view import PacketListView


class PacketView(Frame):
    def __init__(self, main_window, behavior: DefaultBehavior, draw_lock: RLock):
        self.packet_list_view: PacketListView = PacketListView(main_window, behavior, draw_lock)
        super(PacketView, self).__init__(
            self.packet_list_view, AttrMap(Text("   " + behavior.get_header()), "packet_view_header")
        )
        self._socket_information: Union[DefaultBehavior, None] = None
