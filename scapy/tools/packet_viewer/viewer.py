from typing import List, Union, Optional, Dict, Callable
from urwid import AttrMap, MainLoop

from scapy.supersocket import SuperSocket
from scapy.tools.packet_viewer.main_window import MainWindow, MainWindowColumn


def viewer(
    socket,  # type: SuperSocket
    columns=None,  # type: Optional[List[MainWindowColumn]]
    basecls=None,
    **kwargs
):
    palette = [
        ("default", "light gray", "black"),
        ("header", "light blue", "black"),
        ("packet_view_header", "light cyan", "black"),
        ("focused", "light green", "black"),
        ("unfocused", "black", "black"),
        ("reversed", "standout", "black"),
        ("green", "dark green", "black"),
        ("red", "dark red", "black"),
        ("bold", "light gray,bold", "black"),
        ("bold-blue", "light blue,bold", "black"),
        ("green", "light green", "black"),
        ("bold-yellow", "yellow,bold", "black"),
        ("bold-orange", "", "black", "", "", "#f80"),
        ("bold-red", "dark red,bold", "black"),
        ("bg background", "light gray", "black"),
        ("bg 1", "black", "dark blue", "standout"),
        ("bg 2", "black", "dark cyan", "standout"),
        ("bg 1 line", "dark red", "dark blue"),
        ("bg 2 line", "dark red", "dark cyan"),
    ]

    main_window = AttrMap(
        MainWindow(socket, columns, basecls, **kwargs), "default"
    )
    # main_window is the top most widget used to render the whole screen
    loop = MainLoop(main_window, palette)
    main_window.base_widget.main_loop = loop
    main_window.base_widget.packet_view.main_loop = loop
    loop.run()


def get_isotp_preset():
    # type: (...) -> Dict[str, Union[List[MainWindowColumn], Callable]]
    return {"columns": [MainWindowColumn("SRC", 6, lambda p: format(p.src, "03X")),
                        MainWindowColumn("DST", 6, lambda p: format(p.dst, "03X")), ]}


# TODO: This show Identifier(integer?) and ID(hex)
def get_can_preset():
    # type: (...) -> Dict[str, Union[List[MainWindowColumn], Callable]]
    return {
        "columns": [MainWindowColumn("ID", 8, lambda p: format(p.identifier, "03X"))],
    }
