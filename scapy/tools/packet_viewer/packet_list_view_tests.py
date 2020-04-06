import mock
import re
import unittest

from scapy.layers.can import CAN
from scapy.tools.packet_viewer.columns_manager import ColumnsManager
from scapy.tools.packet_viewer.packet_list_view import PacketListView


class PacketListViewTest(unittest.TestCase):
    @mock.patch("scapy.tools.packet_viewer.main_window.MainWindow")
    def setUp(self, main_window_mock):
        self.main_window_mock = main_window_mock

        cm = ColumnsManager(None, CAN)
        self.packet_list_view = PacketListView(main_window_mock, cm)

    def test_packet_received(self):
        packet = CAN(identifier=0x123, data=b'\x90\x0a\xff')
        packet = CAN(bytes(packet))
        self.packet_list_view.add_packet(packet)
        assert len(self.packet_list_view.body) == 1
        assert re.match(r">> 0 +\d*.\d* +11 +291 +3 +0 +b'\\x90\\n\\xff'",
                        self.packet_list_view.body[0].base_widget.text)

        packet = CAN(identifier=0x7ff, data=b'')
        packet = CAN(packet.build())
        self.packet_list_view.add_packet(packet)
        assert len(self.packet_list_view.body) == 2
        assert re.match(r">> 1 +\d*.\d* +8 +2047 +0 +0 +b''.*",
                        self.packet_list_view.body[1].base_widget.text)
