from urwid import Edit

from scapy.tools.packet_viewer.pop_ups import show_info_pop_up


class CommandLineInterface(Edit):
    """
    Widget which takes user input, parses it, passes it to the logic layer
    and displays error messages, in case of incorrect input parameters.
    It is used to control the viewer.
    """

    def __init__(self, main_window):
        """
        :param main_window: the urwid top most widget
        """
        super(CommandLineInterface, self).__init__()
        self.main_window = main_window
        self.set_caption(":")  # required, because the initial focus is on the command line

    def execute_command(
            self, cmd  # type: str
    ):
        cmd = cmd.strip()

        if cmd == "":
            pass
        elif "pause".startswith(cmd):
            self.main_window.pause_packet_sniffer()
        elif "continue".startswith(cmd):
            self.main_window.continue_packet_sniffer()
        elif "quit".startswith(cmd):
            self.main_window.quit()
        else:
            valid_commands = ["pause", "continue", "quit"]
            show_info_pop_up(self.main_window.main_loop, "No valid command, choose from: " + ', '.join(valid_commands))
            return

        self.main_window.focus_position = "body"

    def keypress(self, size, key):
        if key == "enter":
            command = self.get_edit_text()  # type: str
            self.execute_command(command)
            self.set_edit_text("")
            return

        if key == "up":
            self.main_window.focus_position = "body"
            self.remove_display_text()
            return

        super(CommandLineInterface, self).keypress(size, key)

    # Overwrites function from Edit
    # pylint: disable=too-many-arguments
    def mouse_event(self, size, event, button, x, y, focus):
        """
        Handles mouse events.
        """
        if event == "mouse press" and button == 1:
            self.set_caption(":")

    def remove_display_text(self):
        self.set_edit_text("")
        self.set_caption("")
