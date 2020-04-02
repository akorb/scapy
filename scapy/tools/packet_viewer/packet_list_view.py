from urwid import AttrMap, ListBox, SimpleFocusListWalker, connect_signal

from scapy.compat import plain_str
from scapy.packet import Packet
from scapy.tools.packet_viewer.selectable_text import SelectableText

SCROLL_WHEEL_UP = 4
SCROLL_WHEEL_DOWN = 5


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
        body = SimpleFocusListWalker([])
        # registers `self.on_focus_change` as a callback method, whenever the list is modified
        connect_signal(body, "modified", self.on_focus_change)
        super(PacketListView, self).__init__(body)

    def add_packet(
        self, packet  # type: Packet
    ):
        # type: (...) -> None
        """
        Creates and appends a Packet widget to the end of the list.
        The cursor in front of the packet content is colored in the default background color.
        This way, it is invisible and only the cursor in front of the packet in focus is colored.

        :param packet: packet, which is passed on from the sniffer
        :type packet: Packet
        :return: None
        """

        text = self.packet_to_string(packet)
        gui_packet = SelectableText(packet, [("cursor", u">> "), text])

        self.body.append(AttrMap(gui_packet, {"cursor": "unfocused"}, {"cursor": "focused"}))
        if self.main_window.main_loop:
            self.main_window.main_loop.draw_screen()

    def open_packet_details(
        self, is_update=False  # type: bool
    ):
        """
        Gets the packet, currently in focus and creates or updates an existing view with the packets details.
        """
        if self.focus is None:
            return

        packet_in_focus = self.focus.original_widget
        if is_update:
            self.main_window.update_details(packet_in_focus)
        else:
            self.main_window.show_details(packet_in_focus)

    def packet_to_string(
        self, packet  # type: Packet
    ):
        cols = dict()  # type: dict
        for column in self.columns:
            cols[column.name] = plain_str(column.func(packet))[:column.width - 1]

        return self.main_window.format_string.format(**cols)

    def keypress(self, size, key):
        """
        Handles key-presses.
        """

        if key in ["enter", "i"]:
            self.open_packet_details()
            return

        if key == "c":
            self.main_window.close_details()
            return

        super(PacketListView, self).keypress(size, key)

    # Overwrites function from ListBox
    # pylint: disable=too-many-arguments
    def mouse_event(self, size, event, button, col, row, focus):
        """
        Handles mouse events.
        Unhandled mouse events are being passed on to the keypress method of the super class.
        """

        # Translate mouse scrolling to up and down keys
        # to allow scrolling with the scrolling wheel
        if button == SCROLL_WHEEL_UP:
            self.keypress(size, "up")
            return
        if button == SCROLL_WHEEL_DOWN:
            self.keypress(size, "down")
            return

        self.main_window.footer.remove_display_text()
        super(PacketListView, self).mouse_event(size, event, button, col, row, focus)

    def on_focus_change(self):
        """
        Whenever the focus changes from one packet widget to another,
        the cursor of the packet widget previously in focus is colored in the default background color
        and the cursor in front of the packet now in focus is colored in green, so it is visible.
        :return: None
        """

        self.open_packet_details(is_update=True)
