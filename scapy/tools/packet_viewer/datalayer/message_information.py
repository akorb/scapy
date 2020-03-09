from typing import Dict, Tuple, List, Union

from scapy.packet import Packet
from urwid import Text, LineBox

from scapy.tools.packet_viewer.datalayer.funcs import variance, byte_flips, bit_flips, graph_values, bit_flip_correlation
from scapy.tools.packet_viewer.datalayer.behaviors.default_behavior import DefaultBehavior
from scapy.tools.packet_viewer.viewlayer.utils import create_flips_heat_map
from scapy.tools.packet_viewer.viewlayer.views.graph_view import GraphView


# pylint: disable=too-few-public-methods
class MessageInformation:
    def __init__(self, packet: Packet, behavior: DefaultBehavior):
        self.behavior = behavior
        self.count = 1
        # TODO: maybe list of objects with more data, like time, fields and length
        self.all_data = [behavior.get_data(packet)]
        self.all_time = [packet.time]

    def add_packet_information(self, packet: Packet):
        self.count += 1
        self.all_data.append(self.behavior.get_data(packet))
        self.all_time.append(packet.time)


ALL_MESSAGE_INFORMATION: Dict[str, MessageInformation] = {}


def add_new_packet(packet: Packet, behavior: DefaultBehavior) -> MessageInformation:
    identifier = behavior.get_group(packet)
    global ALL_MESSAGE_INFORMATION
    if identifier in ALL_MESSAGE_INFORMATION:
        ALL_MESSAGE_INFORMATION[identifier].add_packet_information(packet)
    else:
        ALL_MESSAGE_INFORMATION[identifier] = MessageInformation(packet, behavior)

    return ALL_MESSAGE_INFORMATION[identifier]


def get_count_and_variance(packet: Packet, behavior: DefaultBehavior) -> Tuple[int, float]:
    identifier = behavior.get_group(packet)
    message_info = ALL_MESSAGE_INFORMATION[identifier]
    time_variance = variance(message_info.all_time, True)
    return message_info.count, time_variance


class MessageDetailsData:
    def __init__(self, group, behavior):
        self.all_data = ALL_MESSAGE_INFORMATION[group].all_data
        self.header = Text(f"   {behavior.get_header()}")
        self.detail_view_header = Text(("bold-blue", "Details"))
        self.byte_heat_map: List[Union[Tuple[str, str], str]] = None
        self.bit_heat_map: List[Union[Tuple[str, str], str]] = None
        self.graph: Union[LineBox, None] = None
        self.corr_coef: Union[Text, None] = None

    def set_detailed_message_information(self):
        byte_changes: Union[List[int], None] = byte_flips(self.all_data)
        bit_changes: Union[List[int], None] = bit_flips(self.all_data)

        self.byte_heat_map = create_flips_heat_map(byte_changes, "Byteflips: ")
        self.bit_heat_map = create_flips_heat_map(bit_changes, "Bitflips: ")

    def create_graph(self):
        graph_data, graph_maximum = graph_values(self.all_data)
        self.graph = LineBox(GraphView(graph_data, graph_maximum), "Data over time")

    def create_bit_correlation(self):
        correlations: Union[List[float], None] = bit_flip_correlation(self.all_data)
        fomatted_corr: List[Union[Tuple[str, str], str]] = [("bold", "Bitflip Correlation of consecutive bits: ")]
        for corr in correlations:
            if corr is None:
                fomatted_corr.append("- | ")
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
            fomatted_corr.append((layout, str(round(corr, 2))))
            fomatted_corr.append(" | ")
        self.corr_coef = Text(fomatted_corr)
