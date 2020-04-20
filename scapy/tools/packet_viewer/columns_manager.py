from itertools import count
from typing import Callable, Dict, List, Optional

from scapy.packet import Packet_metaclass


class ColumnsManager:
    def __init__(
            self,
            columns,  # type: Optional[List[PacketListColumn]]
            cls  # type: Packet_metaclass
    ):
        nr_messages = count()
        # First default columns
        default_cols = [PacketListColumn("NO", 5, lambda p: next(nr_messages)),
                        PacketListColumn("TIME", 20, lambda p: p.time),
                        PacketListColumn("LENGTH", 7, len)]

        # Then user-defined columns
        self.columns = default_cols + (columns or [])

        # Last the fields of the specified cls
        self.columns += [
            PacketListColumn(field.name, max(10, len(field.name) + 1), lambda p, name=field.name: p.getfieldval(name))
            for field in cls.fields_desc]

        self._format_string = self._create_format_string()

    def get_header_string(self):
        # type: (...) -> str
        cols = dict()  # type: Dict[str, str]
        for column in self.columns:
            cols[column.name] = column.name.upper()

        return self._format_string.format(**cols)

    def format(self, packet):
        cols = dict()
        for column in self.columns:
            val = column.func(packet)
            if isinstance(val, str):
                cols[column.name] = repr(val)[:column.width - 1]
            else:
                cols[column.name] = str(val)

        return self._format_string.format(**cols)

    def _create_format_string(self):
        # type: (...) -> str
        format_string = ""
        for column in self.columns:
            format_string += "{" + column.name + ":<" + str(column.width) + "}"
        return format_string


class PacketListColumn:
    """
    Class to define size and content of a column in main view
    """

    def __init__(self, name,  # type: str
                 width,  # type: int
                 func,  # type: Callable
                 ):
        """
        :param name: String that is used as the header of the column
        :param width: Width of the column. Must be at least 1
        :param func: A callable that takes Packet as input and
                     returns what will be displayed in the column
        """
        if width < 1:
            raise ValueError("Columns must have a width of at least 1.")

        self.name = name
        self.width = width
        self.func = func
