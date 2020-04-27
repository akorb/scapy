from typing import Callable, List, Optional, Tuple
from urwid import AttrMap, MainLoop

from scapy.packet import Packet_metaclass
from scapy.supersocket import SuperSocket
from scapy.tools.packet_viewer.main_window import MainWindow


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

    main_window = AttrMap(
        MainWindow(socket, columns, basecls, **kwargs), "default"
    )
    # main_window is the top most widget used to render the whole screen
    loop = MainLoop(main_window, palette)
    main_window.base_widget.main_loop = loop
    main_window.base_widget.packet_view.main_loop = loop
    loop.run()
