from scapy.layers.can import CAN

from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior


class CanBehavior(DefaultBehavior):
    # Do NOT remove the 'socket' parameter. All constructors of all behaviors have to be 'call-compatible'
    def __init__(self, socket):
        additional_columns = [("ID", 8, lambda p: format(self.get_group(p), "03X"))]
        super().__init__(socket, additional_columns)

    def get_data(self, packet: CAN):
        return packet.data

    def get_group(self, packet: CAN):
        # Only packets with the same identifier should be considered in the same group
        return packet.identifier
