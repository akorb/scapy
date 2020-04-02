from urwid import Text


class SelectableText(Text):
    def __init__(self, tag, *args, **kwargs):
        # The tag holds the object this widget represents
        self.tag = tag
        self._selectable = True  # type: bool
        super(SelectableText, self).__init__(*args, **kwargs)

    def keypress(self, size, key):
        # Since this text is selectable, it has to provide a keypress method.
        return key
