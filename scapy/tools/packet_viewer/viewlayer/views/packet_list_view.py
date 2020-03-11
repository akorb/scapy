from scapy.packet import Packet
from urwid import AttrMap, ListBox, SimpleFocusListWalker, connect_signal, Pile

from scapy.tools.packet_viewer.viewlayer.packet import GuiPacket


class PacketListView(ListBox):
    """
    Lists all the packets which have been sniffed so far. Is part of the packet_view.
    """

    def __init__(self, main_window, columns):
        """
        :param main_window: Main window, which contains the packet view
        :type main_window: view.MainWindow
        """

        self.main_window = main_window
        self.columns = columns

        body: SimpleFocusListWalker = SimpleFocusListWalker([])
        # registers `self.on_focus_change` as a callback method, whenever the list is modified
        connect_signal(body, "modified", self.on_focus_change)
        super(PacketListView, self).__init__(body)

    def add_packet(self, packet: Packet):
        """
        Creates and appends a Packet widget to the end of the list.
        The cursor in front of the packet content is colored in the default background color.
        This way, it is invisible and only the cursor in front of the packet in focus is colored.

        :param packet: packet, which is passed on from the sniffer
        :type packet: Packet
        :return: None
        """

        # add_new_packet(packet, behavior)

        text = self.packet_to_string(packet)
        gui_packet = GuiPacket(packet, [("cursor", u">> "), text])

        self.body.append(Pile([AttrMap(gui_packet, {"cursor": "unfocused"})]))

    def open_packet_menu(self):
        """
        Gets the packet, currently in focus and creates a new edit menu,
        which will then allow to edit all the packet fields.
        :return: None
        """

        packet_in_focus = self.body[self.focus_position].get_focus().original_widget
        self.main_window.show_details(packet_in_focus)

    def packet_to_string(self, packet: Packet):
        cols: dict = dict()
        for (name, _, fun) in self.columns:
            cols[name] = str(fun(packet))

        return self.main_window.format_string.format(**cols)

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
