from urwid import Edit


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

    def execute_command(
            self, cmd  # type: str
    ):
        cmd = cmd.strip()

        if cmd == "":
            pass
        elif "pause".startswith(cmd):
            self.main_window.pause_packet_sniffer()
            self.set_unfocused_state()
        elif "continue".startswith(cmd):
            self.main_window.continue_packet_sniffer()
            self.set_unfocused_state()
        elif "quit".startswith(cmd):
            self.main_window.quit()
            self.set_unfocused_state()
        else:
            valid_commands = ["quit", "pause", "continue"]
            self.set_unfocused_state(edit="Error: Invalid command. Choose from: " + ", ".join(valid_commands))

    def keypress(self, size, key):
        if key == "enter":
            command = self.get_edit_text()  # type: str
            self.execute_command(command)
            self.main_window.focus_position = "body"
            return

        if key == "up":
            self.main_window.focus_position = "body"
            self.set_unfocused_state()
            return

        super(CommandLineInterface, self).keypress(size, key)

    # Overwrites function from Edit
    # pylint: disable=too-many-arguments
    def mouse_event(self, size, event, button, x, y, focus):
        """
        Handles mouse events.
        """
        if event == "mouse press" and button == 1:
            self.set_focused_state()

    def set_unfocused_state(self, edit="", caption=""):
        self.set_edit_text(edit)
        self.set_caption(caption)

    def set_focused_state(self, edit="", caption=":"):
        self.set_edit_text(edit)
        self.set_caption(caption)
