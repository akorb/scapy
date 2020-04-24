import six

from itertools import count
from typing import Callable, Dict, List, Optional, Tuple

from scapy.packet import Packet_metaclass


class ColumnsManager:
    def __init__(
            self,
            columns,  # type: Optional[List[Tuple[str, int, Callable]]]
            cls  # type: Packet_metaclass
    ):
        nr_messages = count()
        # First default columns
        default_cols = [("NO", 5, lambda p: next(nr_messages)),
                        ("TIME", 20, lambda p: p.time),
                        ("LENGTH", 7, len)]

        # Then user-defined columns
        self.columns = default_cols + (columns or [])

        # Last the fields of the specified cls
        self.columns += [
            (field.name, 12, lambda p, name=field.name: p.getfieldval(name))
            for field in cls.fields_desc]

        self._format_string = self._create_format_string()

    def get_header_string(self):
        # type: (...) -> str
        cols = dict()  # type: Dict[str, str]
        for name, _, _ in self.columns:
            cols[name] = name.upper()

        return self._format_string.format(**cols)

    def format(self, packet):
        cols = dict()
        for name, width, func in self.columns[:-1]:
            val = func(packet)
            text = self.plain_repr(val)
            cols[name] = text[:width - 1]

        # Do not trim last column. Usually it's the data column
        # so allow it to be as long as necessary
        name, _, func = self.columns[-1]
        val = func(packet)
        text = self.plain_repr(val)
        cols[name] = text

        return self._format_string.format(**cols)

    @staticmethod
    def plain_repr(obj):
        """
        Converts an object to a string.
        It takes care of escaping special characters like '\n'
        and also beautifies the string (no " or b' encapsulating the string).
        :param obj: The object.
        :return: The string.
        """
        if six.PY3 and isinstance(obj, bytes):
            return repr(obj)[2:-1]

        # Calling str first because repr is sometimes not a really "nice"
        # representation of the value.
        # Example: FlagValue.__repr__
        return repr(str(obj))[1:-1]

    def _create_format_string(self):
        # type: (...) -> str
        format_string = ""
        for name, width, _ in self.columns:
            format_string += "{" + name + ":<" + str(width) + "}"
        return format_string
