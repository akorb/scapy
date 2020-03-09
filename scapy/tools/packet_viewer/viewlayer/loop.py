from urwid import MainLoop

# idea from https://github.com/einchan/sshchan/blob/master/display.py
from scapy.tools.packet_viewer.viewlayer.views.main_view import DRAW_LOCK


class Loop(MainLoop):
    """
    Custom implementation of MainLoop, which is thread safe.
    """

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

    def __init__(self, top_widget):
        """Initialize parent class.
        """
        super(Loop, self).__init__(top_widget, self.palette)

    def draw_screen(self):
        """
        Draws the screen, only if the lock can be acquired.
        This guarantees the addition of packets to the view to be thread safe.
        """

        with DRAW_LOCK:
            super(Loop, self).draw_screen()
