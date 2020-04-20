import unittest

from scapy.layers.can import CAN
from scapy.packet import Raw
from scapy.tools.packet_viewer.columns_manager import ColumnsManager, PacketListColumn


class CmdTest(unittest.TestCase):
    @staticmethod
    def assert_column(col, name, width):
        assert col.name == name
        assert col.width == width
        assert col.func is not None

    @staticmethod
    def test_empty_with_Raw():
        cm = ColumnsManager(None, Raw)

        CmdTest.assert_column(cm.columns[0], "NO", 5)
        CmdTest.assert_column(cm.columns[1], "TIME", 20)
        CmdTest.assert_column(cm.columns[2], "LENGTH", 7)

        index = 3
        for f_desc in Raw.fields_desc:
            CmdTest.assert_column(cm.columns[index], f_desc.name, max(10, len(f_desc.name) + 1))
            index += 1

        assert len(cm.columns) == index

    @staticmethod
    def test_with_Can_and_additional_columns():
        columns = [PacketListColumn("SRC", 3, lambda p: format(p.src, "03X")),
                   PacketListColumn("DST", 4, lambda p: format(p.dst, "03X"))]
        cm = ColumnsManager(columns, CAN)

        CmdTest.assert_column(cm.columns[0], "NO", 5)
        CmdTest.assert_column(cm.columns[1], "TIME", 20)
        CmdTest.assert_column(cm.columns[2], "LENGTH", 7)

        CmdTest.assert_column(cm.columns[3], "SRC", 3)
        CmdTest.assert_column(cm.columns[4], "DST", 4)

        index = 5
        for f_desc in CAN.fields_desc:
            CmdTest.assert_column(cm.columns[index], f_desc.name, max(10, len(f_desc.name) + 1))
            index += 1

        assert len(cm.columns) == index

    @staticmethod
    def test_NO_LENGTH():
        cm = ColumnsManager(None, Raw)

        packet = Raw(b'\x01\x02\x03')
        assert cm.columns[0].func(packet) == 0
        assert cm.columns[2].func(packet) == 3

        packet = Raw(b'\xab' * 50)
        assert cm.columns[0].func(packet) == 1
        assert cm.columns[2].func(packet) == 50
