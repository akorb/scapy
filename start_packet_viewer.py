from scapy.tools.packet_viewer.main import viewer

from scapy.contrib.cansocket_native import CANSocket
from scapy.contrib.automotive.obd.obd import OBD
from scapy.contrib.isotp import ISOTPNativeSocket as ISOTPSocket
from scapy.tools.packet_viewer.datalayer.funcs import byte_flips

socket = CANSocket("vcan0")
# socket = ISOTPSocket("vcan0", did=0x123, sid=0x456)
viewer(socket)
socket.close()
