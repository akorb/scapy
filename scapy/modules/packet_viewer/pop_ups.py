# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from typing import Callable, Optional
from urwid import Text, AttrMap, Button, LineBox, Overlay, ListBox, \
    SimpleListWalker, Edit, MainLoop


def show_input_pop_up(loop, caption, initial, button_text, callback,
                      multiline=False, width=100, height=10):
    # type: (MainLoop, str, str, str, Callable[[str], None], Optional[bool], Optional[int], Optional[int]) -> None  # noqa: E501
    """
    Shows a input popup with one editable textfield and three buttons
    :param loop: urwid MainLoop where the popup is shown
    :param caption: Text to describe the input field
    :param initial: Default text in the input field
    :param button_text: Text of the submit button. This button cause
                        the callback to be executed
    :param callback: Function where the input text gets passed to
    :param multiline: Allow multiple lines in input field
    :param width: Width of the popup
    :param height: Height of the popup
    """

    current_widget = loop.widget
    edit = Edit(("default_bold", caption), initial, multiline)

    def delete_overlay(_sender=None):
        loop.widget = current_widget

    def clear_edit(_sender=None):
        edit.edit_text = ""
        edit.edit_pos = 0

    def button_ok(_sender=None):
        ret = callback(edit.edit_text)
        if ret:
            delete_overlay()

    ok_btn = AttrMap(Button(button_text, button_ok), "green")
    clear_btn = AttrMap(Button("Clear", clear_edit), "gray")
    cancel_btn = AttrMap(Button("Cancel", delete_overlay), "red")

    buttons = [edit, ok_btn, clear_btn, cancel_btn]
    prompt = LineBox(ListBox(SimpleListWalker(buttons)))
    overlay = Overlay(prompt, current_widget.base_widget,
                      "center", width, "middle", height, 16, 8)
    loop.widget = overlay
    loop.draw_screen()


def show_info_pop_up(loop, info):
    # type: (MainLoop, str) -> None
    """
    Shows a popup with a information, for example an error message.
    Popup closes on button press
    :param loop: urwid MainLoop where the popup is shown
    :param info: Informationtext
    """
    current_widget = loop.widget

    def delete_overlay(_sender=None):
        loop.widget = current_widget

    info = Text(("default_bold", info), "center")
    ok_btn = AttrMap(Button("OK", delete_overlay), "green")

    prompt = LineBox(ListBox(SimpleListWalker([info, ok_btn])))
    overlay = Overlay(prompt, loop.widget.base_widget, "center",
                      30, "middle", 8, 16, 8)
    loop.widget = overlay
    loop.draw_screen()


def show_question_pop_up(loop, message, yes_callback):
    # type: (MainLoop, str, Callable) -> None
    """
    Shows a popup with a information, for example an error message.
    Popup closes on button press
    :param loop: urwid MainLoop where the popup is shown
    :param message: Question text
    :param yes_callback: Callback which gets called
                         if question is answered with yes
    """
    current_widget = loop.widget

    def delete_overlay(_sender=None):
        loop.widget = current_widget

    question = Text(("default_bold", message), "center")
    no_btn = AttrMap(Button("No", delete_overlay), "red")
    yes_btn = AttrMap(Button("Yes", yes_callback), "green")
    listbox = ListBox(SimpleListWalker([question, yes_btn, no_btn]))
    listbox.focus_position = 2
    linebox = LineBox(listbox)
    overlay = Overlay(linebox, loop.widget.base_widget,
                      "center", 20, "middle", 8, 16, 8)
    loop.widget = overlay
    loop.draw_screen()
