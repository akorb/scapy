# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from typing import Any, Dict, Union
from urwid import ListBox, CanvasCombine, SolidCanvas


class ExtendedListBox(ListBox):
    """
    Implements a ListBox with extended feature.
    These features are:
     - to be rendered even though this listbox is not in focus
     - allow changing selected row with mouse wheel
    """
    def __init__(self, render_always_focused, *args, **kwargs):
        # type: (bool, Any, Dict[str, Any]) -> None
        """
        Initialize ExtendedListBox. args and kwargs are forwarded
        to ListBox
        :param render_always_focused: Configuration for
                                      modified render function
        :param args: args for ListBox
        :param kwargs: kwargs for ListBox
        """
        self.render_always_focused = render_always_focused
        super(ExtendedListBox, self).__init__(*args, **kwargs)

    def mouse_event(self, size, event, button, col, row, focus):
        """
        Translate mouse scrolling to up and down keys to allow scrolling
        with the scrolling wheel
        """
        SCROLL_WHEEL_UP = 4
        SCROLL_WHEEL_DOWN = 5

        if button == SCROLL_WHEEL_UP:
            self.keypress(size, "up")
            return
        if button == SCROLL_WHEEL_DOWN:
            self.keypress(size, "down")
            return

        return super(ExtendedListBox, self).mouse_event(
            size, event, button, col, row, focus)

    def render(self, size, focus=False):
        # type: (int, bool) -> Union[SolidCanvas, CanvasCombine]
        """
        Custom render function
        """
        return super(ExtendedListBox, self).render(
            size, focus=self.render_always_focused or focus)
