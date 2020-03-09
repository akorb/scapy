from typing import List

from urwid import BarGraph, GraphVScale, Columns, Padding


class YScale(GraphVScale):
    """
    Vertical Scala of a Graph 3 values: zero, top and half of top
    """

    def __init__(self, scale: List[float], top: int):
        labels = [[y, str(y)] for y in scale]
        # labels = [(1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5'), (6, '6'), (7, '7'), (8, '8'), (9, '9')]
        super().__init__(labels, top)


class Graph(BarGraph):
    """
    Bar-graph in blue.
    """

    def __init__(self, graph_data: List[List[float]], top: int, scale: List[float]):
        super().__init__(["bg background", "bg 1", "bg 2"], hatt=["red", "bg 1 line", "bg 2 line"])

        # _optional_graph_data = [[value[0], value[0] - 1] for value in graph_data]
        is_even = True

        for index, _ in enumerate(graph_data):
            if is_even:
                graph_data[index] = [0, graph_data[index][0]]
                is_even = False
            else:
                is_even = True
        self.set_data(graph_data, top, scale)  # [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]


class GraphView(Columns):
    def __init__(self, graph_data: List[List[float]], top: int):
        scale = [top * 0.25, top * 0.5, top * 0.75]
        y_scale = YScale(scale, top)
        graph = Graph(graph_data, top, scale)
        y_scale_space = max([len(str(y)) for y in scale]) + 1
        super().__init__([(y_scale_space, Padding(y_scale, left=0, right=1)), graph])
