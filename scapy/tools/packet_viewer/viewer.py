from typing import List, Union, Optional, Dict, Callable
from urwid import AttrMap, MainLoop

from scapy.packet import Packet_metaclass, Raw
from scapy.supersocket import SuperSocket
from scapy.tools.packet_viewer.columns_manager import PacketListColumn
from scapy.tools.packet_viewer.main_window import MainWindow


def viewer(
    socket,  # type: SuperSocket
    columns=None,  # type: Optional[List[PacketListColumn]]
    basecls=None,  # type: Packet_metaclass
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

    basecls = basecls if basecls else getattr(socket, "basecls", Raw)

    main_window = AttrMap(
        MainWindow(socket, columns, basecls, **kwargs), "default"
    )
    # main_window is the top most widget used to render the whole screen
    loop = MainLoop(main_window, palette)
    main_window.base_widget.main_loop = loop
    main_window.base_widget.packet_view.main_loop = loop
    loop.run()


def get_isotp_preset():
    # type: (...) -> Dict[str, Union[List[PacketListColumn], Callable]]
    return {"columns": [PacketListColumn("SRC", 6, lambda p: format(p.src, "03X")),
                        PacketListColumn("DST", 6, lambda p: format(p.dst, "03X")), ]}


# TODO: This show Identifier(integer?) and ID(hex)
def get_can_preset():
    # type: (...) -> Dict[str, Union[List[PacketListColumn], Callable]]
    return {
        "columns": [PacketListColumn("ID", 8, lambda p: format(p.identifier, "03X"))],
    }
