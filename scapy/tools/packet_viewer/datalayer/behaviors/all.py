from scapy.contrib.isotp import ISOTP
from scapy.layers.can import CAN

from scapy.tools.packet_viewer.datalayer.behaviors.can_behavior import CanBehavior
from scapy.tools.packet_viewer.datalayer.behaviors.isotp_behavior import IsotpBehavior

DIC_SOCKET_INFORMATION = {CAN: CanBehavior, ISOTP: IsotpBehavior}
