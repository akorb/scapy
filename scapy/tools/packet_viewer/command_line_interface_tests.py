import unittest

import mock

from scapy.tools.packet_viewer.command_line_interface import CommandLineInterface


class TextTest(unittest.TestCase):
    @mock.patch("scapy.tools.packet_viewer.main_window.MainWindow")
    def setUp(self, main_window_mock):
        self.main_window_mock = main_window_mock
        self.command_line = CommandLineInterface(main_window_mock)

    def assert_command_execution(self, command=None, func=None, key="enter"):
        if command:
            self.command_line.set_edit_text(command)
        self.command_line.keypress((12,), key)

        if func:
            func.assert_called_once()

        expected_edit_text = ''
        got = self.command_line.edit_text
        assert got == expected_edit_text, "got: %r expected: %r" % (got, expected_edit_text)

        expected_caption_text = ''
        got = self.command_line.caption
        assert got == expected_caption_text, "got: %r expected: %r" % (got, expected_caption_text)

    def test_focus_text(self):
        expected_text = [b' ']
        got = self.command_line.render((1,)).text
        assert got == expected_text, "got: %r expected: %r" % (got, expected_text)

    def test_execute_empty_command(self):
        self.assert_command_execution()

    def test_execute_up_command(self):
        self.assert_command_execution(key="up")

    def test_execute_pause_command(self):
        self.assert_command_execution("pause", self.main_window_mock.pause_packet_sniffer)

    def test_execute_pause_command_partial(self):
        self.assert_command_execution("pau", self.main_window_mock.pause_packet_sniffer)

    def test_execute_pause_command_single(self):
        self.assert_command_execution("p", self.main_window_mock.pause_packet_sniffer)

    def test_execute_quit_command(self):
        self.assert_command_execution("quit", self.main_window_mock.quit)

    def test_execute_quit_command_partial(self):
        self.assert_command_execution("qu", self.main_window_mock.quit)

    def test_execute_quit_command_single(self):
        self.assert_command_execution("q", self.main_window_mock.quit)

    def test_execute_continue_command(self):
        self.assert_command_execution("continue", self.main_window_mock.continue_packet_sniffer)

    def test_execute_continue_command_partial(self):
        self.assert_command_execution("cont", self.main_window_mock.continue_packet_sniffer)

    def test_execute_continue_command_single(self):
        self.assert_command_execution("c", self.main_window_mock.continue_packet_sniffer)
