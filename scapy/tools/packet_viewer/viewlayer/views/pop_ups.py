import sys

from urwid import Text, AttrMap, Button, LineBox, Overlay, ListBox, SimpleFocusListWalker, ExitMainLoop

from scapy.error import Scapy_Exception


def show_info_pop_up(loop, info):
    current_widget = loop.widget

    def delete_overlay(_self):
        loop.widget = current_widget

    info = Text(("bold", info), "center")
    ok_btn = AttrMap(Button("OK", delete_overlay), "green")

    prompt = LineBox(ListBox(SimpleFocusListWalker([info, ok_btn])))
    overlay = Overlay(prompt, loop.widget.base_widget, "center", 30, "middle", 8, 16, 8)
    loop.widget = overlay
    loop.draw_screen()


def show_exit_pop_up(main_window):
    current_widget = main_window.main_loop.widget

    def delete_overlay(_self):
        print("delete overlay")
        main_window.main_loop.widget = current_widget

    def exit_loop(_self):
        try:
            main_window.sniffer.stop(False)
        except Scapy_Exception:
            pass

        print("exit loop")
        raise ExitMainLoop()

    question = Text(("bold", "Really quit?"), "center")
    yes_btn = AttrMap(Button("Yes", exit_loop), "red")
    no_btn = AttrMap(Button("No", delete_overlay), "green")
    prompt = LineBox(ListBox(SimpleFocusListWalker([question, no_btn, yes_btn])))
    overlay = Overlay(prompt, main_window.main_loop.widget.base_widget, "center", 20, "middle", 8, 16, 8)
    main_window.main_loop.widget = overlay
