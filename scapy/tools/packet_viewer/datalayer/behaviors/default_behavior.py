from scapy.packet import Packet
from scapy.supersocket import SuperSocket


class DefaultBehavior:
    # Do NOT remove the 'socket' parameter. All constructors of all behaviors have to be 'call-compatible'
    # Also the 'additional_columns' parameter is usually used by sub classes, but not restricted to it.
    def __init__(self, socket: SuperSocket, basecls, additional_columns: list = None):
        self.counter = 0
        # Tuple: Name, length of column, function to get the value from (lambda p: p.identifier)
        self.basecls = socket.basecls if hasattr(socket, 'basecls') else basecls
        self.packets = {}
        self.columns = [('TIME', 20, lambda p: str(p.time)),
                        ('LENGTH', 5, lambda p: str(len(p)))]

        self.columns += additional_columns

        self.format_string = ""
        for (name, length, _) in self.columns:
            self.format_string += "{" + name + ":<" + str(length) + "}"

    def get_data(self, packet):
        # bytearray is important for Py2 compatibility
        return bytearray(bytes(packet))

    def get_header(self) -> str:
        cols: dict = dict()
        for (name, _, _) in self.columns:
            cols[name] = name.upper()

        return self._format_strings(**cols)

    def get_group(self, packet):
        # by default all packets with the same length are considered to be in the same group
        length = len(packet)
        return length

    def _format_strings(self, **kwargs):
        return self.format_string.format(**kwargs)

    def get_packet_formatted(self, packet: Packet):
        cols: dict = dict()
        for (name, _, fun) in self.columns:
            cols[name] = fun(packet)

        return self._format_strings(**cols)
