import threading
import time

from scapy.contrib.cansocket_python_can import PythonCANSocket
from scapy.layers.can import CAN
from scapy.tools.packet_viewer.viewer import viewer, get_can_preset_py2


def send_msg():
    socket2 = PythonCANSocket(bustype="virtual", channel="vcan1")

    for i in range(10):
        # TODO: if you use a bytestring it tries to encode the bytes in python2 and returns mostly questionmarks
        # socket2.send(CAN(identifier=0x602, data=b'\x24\x89'))
        socket2.send(CAN(identifier=0x1001, data="test" + str(i)))
        time.sleep(1)


socket = PythonCANSocket(bustype="virtual", channel="vcan1")
thread1 = threading.Thread(target=send_msg)
thread1.start()

viewer(socket, basecls=socket.basecls, **get_can_preset_py2())

thread1.join()

socket.close()
