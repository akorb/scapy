from typing import List, Union, Tuple, Dict, Callable
from urwid import AttrMap, MainLoop

from scapy.supersocket import SuperSocket
from scapy.compat import bytes_hex
from scapy.tools.packet_viewer.viewlayer.views.main_view import MainWindow


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
        ("bold-yellow", "yellow, bold ", "black"),
        ("bold-orange", "", "black", "", "", "#f80"),
        ("bold-red", "dark red, bold ", "black"),
        ("bg background", "light gray", "black"),
        ("bg 1", "black", "dark blue", "standout"),
        ("bg 2", "black", "dark cyan", "standout"),
        ("bg 1 line", "dark red", "dark blue"),
        ("bg 2 line", "dark red", "dark cyan"),
    ]  # type: List[Union[Tuple[str, str, str],Tuple[str, str, str, str], Tuple[str, str, str, str, str, str] ]]

def viewer(*args, **kwargs):
    main_window = \
        AttrMap(MainWindow(*args, **kwargs), "default")  # type: AttrMap
    # main_window is the top most widget used to render the whole screen
    loop = MainLoop(main_window, palette)  # type: MainLoop
    main_window.base_widget.main_loop = loop
    loop.run()


def get_isotp_preset():
    # type: (...) -> Dict[str, List[Tuple[str, int, Callable]]]
    return {"columns": [("SRC", 6, lambda p: format(p.src, "03X")),
                        ("DST", 6, lambda p: format(p.dst, "03X")),]}


# TODO: This show Identifier(integer?) and ID(hex)
def get_can_preset():
    # type: (...) -> Dict[str, Union[List[Tuple], Callable]]
    return {
        "columns": [("ID", 8, lambda p: format(p.identifier, "03X"))],
        "get_group": lambda p: p.identifier,
        "get_data": lambda p: bytes_hex(p.data),
    }
