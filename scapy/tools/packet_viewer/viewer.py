from urwid import AttrMap, MainLoop

from scapy.packet import Raw
from scapy.tools.packet_viewer.viewlayer.views.main_view import MainWindow


def viewer(socket,
           columns=None,
           get_group=lambda p: len(p),
           get_data=lambda p: bytearray(bytes(p)),
           basecls=Raw, **kwargs):
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
    ]

    main_window: AttrMap = AttrMap(MainWindow(socket, columns, get_group, get_data, basecls, **kwargs), "default")
    # main_window is the top most widget used to render the whole screen
    loop: MainLoop = MainLoop(main_window, palette)
    main_window.base_widget.main_loop = loop
    loop.run()


def get_isotp_preset(socket):
    return \
        {
            'columns':
            [
                ("SRC", 6, lambda p: format(p.src, "03X")),
                ("DST", 6, lambda p: format(p.dst, "03X")),
            ]
        }


def get_can_preset():
    return \
        {
            'columns': [("ID", 8, lambda p: format(p.identifier, "03X"))],
            'get_group': lambda p: p.identifier,
            'get_data': lambda p: p.data
        }
