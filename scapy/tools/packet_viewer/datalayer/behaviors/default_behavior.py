from abc import ABC

from scapy.packet import Packet
from scapy.supersocket import SuperSocket


class DefaultBehavior(ABC):
    # Do NOT remove the 'socket' parameter. All constructors of all behaviors have to be 'call-compatible'
    # Also the 'additional_columns' parameter is usually used by sub classes, but not restricted to it.
    def __init__(self, socket: SuperSocket, basecls, additional_columns: list = None):
        self.counter = 0
        # Tuple: Name, length of column, function to get the value from (lambda p: p.identifier)
        self.basecls = socket.basecls if hasattr(socket, 'basecls') else basecls
        self.additional_columns: list = additional_columns or []
        self.packets = {}

    def get_data(self, packet):
        # bytearray is important for Py2 compatibility
        return bytearray(bytes(packet))

    def get_header(self) -> str:
        cols: dict = dict()
        for (name, _, _) in self.additional_columns:
            cols[name] = name.upper()

        for field in self.basecls.fields_desc:
            cols[field.name] = field.name.upper()

        return self._format_strings(time="TIME", **cols)

    def get_group(self, packet):
        # by default all packets are considered to be in the same group
        length = len(packet)
        return length

    def _format_strings(self, **kwargs):
        template: str = self._get_format_string()
        for key, value in kwargs.items():
            kwargs[key] = str(value)
        return template.format(**kwargs)

    def _get_format_string(self) -> str:
        # First column is TIME
        # space for cursor
        format_str = "{time:<20}"

        obj = self.basecls()
        obj.build()

        # Now add additional columns
        for (name, length, _) in self.additional_columns:
            format_str += "{" + name + ":<" + str(length) + "}"

        for field in self.basecls.fields_desc:
            format_str += "{" + field.name + ":<" + str(obj.fields[field.name]) + "}"

        return format_str

    def get_packet_formatted(self, packet: Packet):
        cols: dict = packet.fields.copy()
        for (name, _, fun) in self.additional_columns:
            cols[name] = fun(packet)

        return self._format_strings(time=packet.time, **cols)
