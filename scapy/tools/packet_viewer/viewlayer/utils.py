from typing import List, Union, Tuple

from urwid import Text


def create_flips_heat_map(flips: Union[List[int], None], name: str) -> List[Union[Tuple[str, str], str]]:
    if not flips:
        return Text([("bold", name), ": could not be generated"])

    max_flips: int = max(flips)

    all_flips_text: List[Union[Tuple[str, str], str]] = [("bold", name)]
    for flip in flips:
        if flip == 0:
            layout = "green"
        elif flip == max_flips:
            layout = "bold-red"
        elif flip <= max_flips / 2:
            layout = "bold-yellow"
        else:
            layout = "bold-orange"
        all_flips_text.append((layout, str(flip)))
        all_flips_text.append(" | ")

    text = Text(all_flips_text)
    return text
