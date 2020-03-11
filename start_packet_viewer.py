from scapy.arch import L2Socket
from scapy.contrib.cansocket_python_can import PythonCANSocket
from scapy.contrib.cansocket_native import CANSocket
from scapy.contrib.isotp import ISOTPNativeSocket as ISOTPSocket
from scapy.layers.can import CAN
from scapy.layers.l2 import Ether
from scapy.tools.packet_viewer.viewer import viewer

socket = ISOTPSocket("vcan0", did=0x123, sid=0x456)
# socket = PythonCANSocket(bustype='virtual', channel="vcan1")
# socket = CANSocket("vcan0")
# socket = L2Socket("enp4s0")
viewer(socket, socket.basecls)
# viewer(socket, Ether)
socket.close()
