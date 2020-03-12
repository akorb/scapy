import shlex
from argparse import ArgumentParser as NativeArgumentParser, Namespace

from scapy.tools.packet_viewer.viewlayer.views.pop_ups import show_info_pop_up
from typing import Tuple, Union
from urwid import Edit


class ArgumentError(Exception):
    pass


class ArgumentParser(NativeArgumentParser):
    def error(self, message):
        raise ArgumentError(message)


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
        self.sniffer = None

    def execute_command(
        self, infos  # type: Namespace
    ):
        if infos.cmd == "pause":
            self.main_window.pause_packet_sniffer()
        elif infos.cmd == "continue":
            self.main_window.continue_packet_sniffer()
        elif infos.cmd == "quit":
            self.main_window.quit()

    def keypress(self, size, key):
        if key == "enter":
            text = self.get_edit_text()  # type: str
            success, infos_or_error = self._parse_user_input(text)
            if success:
                self.execute_command(infos_or_error)
            else:
                show_info_pop_up(self.main_window.main_loop, infos_or_error)

            self.set_edit_text("")
        elif key == "up":
            self.main_window.focus_position = "body"
            self.remove_display_text()
        else:
            super(CommandLineInterface, self).keypress(size, key)

    @staticmethod
    def _parse_user_input(
        text,  # type: str
    ):
        # type: (...) -> Tuple[bool, Union[str, Namespace]]
        """
        :param text: The input of the user.
        :return: First parameter determines if input was valid.
                 Second parameter contains information the user specified if valid input, otherwise error message.
        """
        parser = ArgumentParser()
        parser.add_argument("cmd", choices=["pause", "continue", "quit"])

        split_text = shlex.split(text)

        try:
            args = parser.parse_args(split_text)
        except ArgumentError as ex:
            return False, ex.args[0]

        return True, args

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
