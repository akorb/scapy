import unittest

import mock

from scapy.tools.packet_viewer.command_line_interface import CommandLineInterface


class TextTest(unittest.TestCase):
    @mock.patch("scapy.tools.packet_viewer.main_window.MainWindow")
    def setUp(self, main_window_mock):
        self.main_window_mock = main_window_mock
        self.command_line = CommandLineInterface(main_window_mock)

    def test_focus_text(self):
        expected_text = [':']
        got = self.command_line.render((1,)).text
        assert got == expected_text, "got: %r expected: %r" % (got, expected_text)

    def test_execute_empty_command(self):
        self.command_line.keypress((12,), "enter")

        expected_edit_text = ''
        got = self.command_line.edit_text
        assert got == expected_edit_text, "got: %r expected: %r" % (got, expected_edit_text)

        expected_caption_text = ':'
        got = self.command_line.caption
        assert got == expected_caption_text, "got: %r expected: %r" % (got, expected_caption_text)

    def test_execute_up_command(self):
        self.command_line.keypress((12,), "up")

        expected_edit_text = ''
        got = self.command_line.edit_text
        assert got == expected_edit_text, "got: %r expected: %r" % (got, expected_edit_text)

        expected_caption_text = ''
        got = self.command_line.caption
        assert got == expected_caption_text, "got: %r expected: %r" % (got, expected_caption_text)

    def test_execute_pause_command(self):
        self.command_line.set_edit_text('pause')
        self.command_line.keypress((12,), "enter")

        self.main_window_mock.pause_packet_sniffer.assert_called_once()

        expected_edit_text = ''
        got = self.command_line.edit_text
        assert got == expected_edit_text, "got: %r expected: %r" % (got, expected_edit_text)

        expected_caption_text = ':'
        got = self.command_line.caption
        assert got == expected_caption_text, "got: %r expected: %r" % (got, expected_caption_text)

    def test_execute_quit_command(self):
        self.command_line.set_edit_text('quit')
        self.command_line.keypress((12,), "enter")

        self.main_window_mock.quit.assert_called_once()

        expected_edit_text = ''
        got = self.command_line.edit_text
        assert got == expected_edit_text, "got: %r expected: %r" % (got, expected_edit_text)

        expected_caption_text = ':'
        got = self.command_line.caption
        assert got == expected_caption_text, "got: %r expected: %r" % (got, expected_caption_text)

    def test_execute_continue_command(self):
        self.command_line.set_edit_text('continue')
        self.command_line.keypress((12,), "enter")

        self.main_window_mock.continue_packet_sniffer.assert_called_once()

        expected_edit_text = ''
        got = self.command_line.edit_text
        assert got == expected_edit_text, "got: %r expected: %r" % (got, expected_edit_text)

        expected_caption_text = ':'
        got = self.command_line.caption
        assert got == expected_caption_text, "got: %r expected: %r" % (got, expected_caption_text)
