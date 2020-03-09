from threading import RLock

from scapy.packet import Packet
from urwid import AttrMap, ListBox, SimpleFocusListWalker, connect_signal, Pile

from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior
from scapy.tools.packet_viewer.datalayer.message_information import add_new_packet
from scapy.tools.packet_viewer.viewlayer.packet import GuiPacket
from scapy.tools.packet_viewer.viewlayer.views.menu_view import open_menu


class PacketListView(ListBox):
    """
    Lists all the packets which have been sniffed so far. Is part of the packet_view.
    """

    def __init__(self, main_window, behavior: DefaultBehavior, draw_lock: RLock):
        """
        :param main_window: Main window, which contains the packetview
        :type main_window: view.MainWindow
        :param draw_lock: lock, which makes sure the view.MainLoop can redraw the interface for every new packet
        :type draw_lock: RLock
        """

        self.main_window = main_window
        self.behavior = behavior
        self.draw_lock: RLock = draw_lock

        body: SimpleFocusListWalker = SimpleFocusListWalker([])
        # registers `self.on_focus_change` as a callback method, whenever the list is modified
        connect_signal(body, "modified", self.on_focus_change)
        super(PacketListView, self).__init__(body)

    def add_packet(self, the_packet: Packet):
        """
        Creates and appends a Packet widget to the end of the list.
        The cursor in front of the packet content is colored in the default background color.
        This way, it is invisible and only the cursor in front of the packet in focus is colored.

        :param the_packet: packet, which is passed on from the sniffer
        :type the_packet: Packet
        :return: None
        """

        add_new_packet(the_packet, self.behavior)
        self.body.append(Pile([AttrMap(GuiPacket(the_packet, self.behavior), {"cursor": "unfocused"})]))
        self.main_window.main_loop.draw_screen()

    def open_packet_menu(self):
        """
        Gets the packet, currently in focus and creates a new edit menu,
        which will then allow to edit all the packet fields.
        :return: None
        """

        packet_in_focus = self.body[self.focus_position].get_focus().original_widget
        # TODO: new detail-view instead of menu
        open_menu(self.main_window, self.behavior, packet_in_focus)

    def keypress(self, size, key):
        """
        Handles key-presses.
        """

        if key in ["up", "k"]:
            focus = self.body.get_focus()[1]
            if focus:
                next_focus = focus - 1
                if next_focus >= 0:
                    self.body.set_focus(next_focus)
        elif key in ["down", "j"]:
            if self.main_window.sniffer is None:
                self.main_window.footer.set_caption(":")
                self.main_window.set_focus("footer")
                return
            focus = self.body.get_focus()[1]
            if focus is not None:
                next_focus = focus + 1
                if next_focus < len(self.body):
                    self.body.set_focus(next_focus)
        elif key in ["enter", "i"]:
            self.open_packet_menu()

    # Overwrites function from ListBox
    # pylint: disable=too-many-arguments
    def mouse_event(self, size, event, button, col, row, focus):
        """
        Handles mouse events.
        Unhandled mouse events are being passed on to the keypress method of the super class.
        """

        self.main_window.footer.remove_display_text()
        super(PacketListView, self).mouse_event(size, event, button, col, row, focus)

    def on_focus_change(self):
        """
        Whenever the focus changes from one packet widget to another,
        the cursor of the packet widget previously in focus is colored in the default background color
        and the cursor in front of the packet now in focus is colored in green, so it is visible.
        :return: None
        """

        packet_in_focus = self.body[self.focus_position].get_focus()
        packet_in_focus.set_focus_map({"cursor": "focused"})
