# from scapy.arch import L2Socket
import threading
import time

from scapy.contrib.cansocket_python_can import PythonCANSocket
from scapy.contrib.cansocket_native import CANSocket
# from scapy.contrib.isotp import ISOTPNativeSocket as ISOTPSocket
from scapy.layers.can import CAN
from scapy.tools.packet_viewer.viewer import viewer, get_can_preset

# socket = ISOTPSocket("vcan0", did=0x123, sid=0x456)
# socket = PythonCANSocket(bustype='virtual', channel="vcan1")
socket = CANSocket("vcan0")
# socket = L2Socket("enp4s0")
# viewer(socket, basecls=socket.basecls, **get_isotp_preset())
viewer(socket, basecls=socket.basecls, **get_can_preset())
# viewer(socket, Ether)
# socket.close()


# def send_msg():
#     socket2 = PythonCANSocket(bustype="virtual", channel="vcan1")
#
#     for i in range(10):
#         # TODO: if you use a bytestring it tries to encode the bytes in python2 and returns mostly questionmarks
#         # socket2.send(CAN(identifier=0x602, data=b'\x24\x89'))
#         socket2.send(CAN(identifier=0x1001, data="test"))
#         time.sleep(1)
#
#
# socket = PythonCANSocket(bustype="virtual", channel="vcan1")
# thread1 = threading.Thread(target=send_msg)
# thread1.start()
#
# viewer(socket, basecls=socket.basecls)
#
# thread1.join()
#
# socket.close()
