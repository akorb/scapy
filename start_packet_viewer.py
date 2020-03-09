from scapy.contrib.cansocket_python_can import PythonCANSocket
from scapy.contrib.cansocket_native import CANSocket
from scapy.contrib.isotp import ISOTPNativeSocket as ISOTPSocket
from scapy.tools.packet_viewer.viewer import viewer

# socket = ISOTPSocket("vcan0", did=0x123, sid=0x456)
# socket = PythonCANSocket(bustype='virtual', channel="vcan1")
socket = CANSocket("can0")
viewer(socket)
socket.close()
