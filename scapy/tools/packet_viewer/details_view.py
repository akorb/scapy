from urwid import Button, AttrMap, Text, Columns, LineBox, Filler

from scapy.packet import Packet
from scapy.utils import hexdump


class DetailsView(LineBox):
    def __init__(self, close_details_func):
        self.visible = False
        close_btn = AttrMap(Button("Close details (press this button or click c)", close_details_func), "green")
        self.close_btn_widget = (close_btn, ("pack", None))
        self.detail_text = Text("")
        self.hex_text = Text("", align="right")
        col = Columns([("pack", self.detail_text), self.hex_text], dividechars=4)
        super(DetailsView, self).__init__(Filler(col, "top"))

    def update(
            self, packet  # type: Packet
    ):
        self.detail_text.set_text(packet.show(dump=True))
        self.hex_text.set_text(hexdump(packet, dump=True))
