import threading
import time

from scapy.contrib.cansocket_python_can import PythonCANSocket
from scapy.layers.can import CAN
from scapy.tools.packet_viewer.viewer import viewer, get_can_preset


def send_msg():
    socket2 = PythonCANSocket(bustype='virtual', channel="vcan1")

    for i in range(10):
        socket2.send(CAN(flags=["extended"], identifier=0x123456, data="test" + str(i)))
        time.sleep(1)


# socket = ISOTPSocket("can0", did=0x123, sid=0x456)
socket = PythonCANSocket(bustype='virtual', channel="vcan1")
thread1 = threading.Thread(target=send_msg)
thread1.start()

viewer(socket, **get_can_preset())

thread1.join()

socket.close()
