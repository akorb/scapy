from urwid import Button, AttrMap, Text, Columns, LineBox, Filler

from scapy.tools.packet_viewer.gui_packet import GuiPacket
from scapy.utils import hexdump


class DetailsView:
    def __init__(self, visible, close_details_func):
        self.visible = visible
        close_btn = AttrMap(Button("Close details (press this button or click c)", close_details_func), "green")
        self.close_btn_widget = (close_btn, ("pack", None))

    def create_details_view(
            self, packet  # type: GuiPacket
    ):
        show_text = packet.packet.show(dump=True)

        show_text = Text(show_text)
        hexdump_text = Text(hexdump(packet.packet, dump=True), align="right")

        col = Columns([("pack", show_text), hexdump_text], dividechars=4)
        linebox = LineBox(Filler(col, "top"))

        return linebox, ("weight", 0.3)
