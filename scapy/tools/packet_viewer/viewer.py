from urwid import AttrMap

from scapy.tools.packet_viewer.viewlayer.loop import Loop
from scapy.tools.packet_viewer.viewlayer.views.main_view import MainWindow


def viewer(socket, **kwargs):
    main_window: AttrMap = AttrMap(MainWindow(socket, **kwargs), "default")
    # main_window is the top most widget used to render the whole screen
    loop: Loop = Loop(main_window)
    main_window.base_widget.main_loop = loop
    loop.run()
