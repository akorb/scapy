from typing import Dict, Tuple, List, Union, Optional
from urwid import Text, LineBox

from scapy.packet import Packet
from scapy.tools.packet_viewer.datalayer.funcs import (
    variance,
    byte_flips,
    bit_flips,
    graph_values,
    bit_flip_correlation,
)
from scapy.tools.packet_viewer.viewlayer.utils import create_flips_heat_map
from scapy.tools.packet_viewer.viewlayer.views.graph_view import GraphView


# pylint: disable=too-few-public-methods
class MessageInformation:
    def __init__(self, packet, data):  # tape : Packet,
        self.count = 1
        # TODO: maybe list of objects with more data, like time, fields and length
        self.all_data = [data]
        self.all_time = [packet.time]

    def add_packet_information(
        self,
        packet,  # type: Packet
        data,
    ):
        self.count += 1
        self.all_data.append(data)
        self.all_time.append(packet.time)


ALL_MESSAGE_INFORMATION = {}  # type: Dict[str, MessageInformation]


def add_new_packet(
    packet,  # type: Packet
    group,  # type: str
    data,  # type: str
):
    # type:(...)-> MessageInformation
    global ALL_MESSAGE_INFORMATION
    if group in ALL_MESSAGE_INFORMATION:
        ALL_MESSAGE_INFORMATION[group].add_packet_information(packet, data)
    else:
        ALL_MESSAGE_INFORMATION[group] = MessageInformation(packet, "temp header")

    return ALL_MESSAGE_INFORMATION[group]


def get_count_and_variance(group):
    # type: (...) -> Tuple[int, float]
    message_info = ALL_MESSAGE_INFORMATION[group]
    time_variance = variance(message_info.all_time, True)
    return message_info.count, time_variance


class MessageDetailsData:
    def __init__(
        self, group, header  # type: str
    ):
        self.all_data = ALL_MESSAGE_INFORMATION[group].all_data
        self.header = Text("   " + header)
        self.detail_view_header = Text(("bold-blue", "Details"))
        self.byte_heat_map = []  # type: List[Union[Tuple[str, str], str]]
        self.bit_heat_map = []  # type: List[Union[Tuple[str, str], str]]
        self.graph = None  # type:Optional[LineBox]
        self.corr_coef = None  # type: Optional[Text]

    def set_detailed_message_information(self):
        byte_changes = byte_flips(self.all_data)  # type: Optional[List[int]]
        bit_changes = bit_flips(self.all_data)  # type: Optional[List[int]]

        self.byte_heat_map = create_flips_heat_map(byte_changes, "Byteflips: ")
        self.bit_heat_map = create_flips_heat_map(bit_changes, "Bitflips: ")

    def create_graph(self):
        graph_data, graph_maximum = graph_values(self.all_data)
        self.graph = LineBox(GraphView(graph_data, graph_maximum), "Data over time")

    def create_bit_correlation(self):
        correlations = bit_flip_correlation(self.all_data)  # type: Optional[List[float]]
        formatted_corr = [
            ("bold", "Bitflip Correlation of consecutive bits: ")
        ]  # type: List[Union[Tuple[str, str], str]]
        for corr in correlations:
            if corr is None:
                formatted_corr.append("- | ")
                continue
            if corr == 0:
                layout = "default"
            elif 0 < corr < 0.5:
                layout = "bold-yellow"
            elif corr <= 0.5:
                layout = "green"
            elif 0 > corr >= -0.5:
                layout = "bold-orange"
            else:
                layout = "bold-red"
            formatted_corr.append((layout, str(round(corr, 2))))
            formatted_corr.append(" | ")
        self.corr_coef = Text(formatted_corr)
