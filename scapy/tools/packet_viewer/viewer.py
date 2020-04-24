from typing import Callable, List, Optional, Tuple
from urwid import AttrMap, MainLoop

from scapy.config import conf
from scapy.contrib.isotp import ISOTP
from scapy.layers.can import CAN
from scapy.packet import Packet_metaclass, Raw
from scapy.supersocket import SuperSocket
from scapy.tools.packet_viewer.main_window import MainWindow

conf.contribs["packet_viewer_columns"] = {
    ISOTP: [("SRC", 6, lambda p: format(p.src, "03X")),
            ("DST", 6, lambda p: format(p.dst, "03X"))],

    CAN: [("ID", 8, lambda p: format(p.identifier, "03X"))]
}


def viewer(
        socket,  # type: SuperSocket
        columns=None,  # type: Optional[List[Tuple[str, int, Callable]]]
        basecls=None,  # type: Optional[Packet_metaclass]
        **kwargs
):
    palette = [
        ("default", "light gray", "black"),
        ("header", "light blue", "black"),
        ("packet_view_header", "light cyan", "black"),
        ("cursor_focused", "light green", "black"),
        ("cursor_unfocused", "black", "black"),
        ("green", "dark green", "black"),
        ("red", "dark red", "black"),
        ("default_bold", "light gray,bold", "black"),
    ]

    basecls = basecls or getattr(socket, "basecls", Raw)

    if columns is None:
        columns = conf.contribs["packet_viewer_columns"].get(basecls)

    main_window = AttrMap(
        MainWindow(socket, columns, basecls, **kwargs), "default"
    )
    # main_window is the top most widget used to render the whole screen
    loop = MainLoop(main_window, palette)
    main_window.base_widget.main_loop = loop
    main_window.base_widget.packet_view.main_loop = loop
    loop.run()
