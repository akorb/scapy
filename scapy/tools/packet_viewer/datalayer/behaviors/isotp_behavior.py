from scapy.contrib.isotp import ISOTP
from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior


class IsotpBehavior(DefaultBehavior):
    def __init__(self, socket, basecls):
        additional_columns = [
            ("SRC", 6, lambda p: format(self.src, "03X")),
            ("DST", 6, lambda p: format(self.dst, "03X")),
        ]
        super().__init__(socket, ISOTP, additional_columns)
        self.src = socket.src
        self.dst = socket.dst
