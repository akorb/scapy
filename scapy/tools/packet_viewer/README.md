# Usage


Start viewer with Python Script.
```python
from scapy.tools.packet_viewer.viewer import viewer

from scapy.contrib.cansocket_native import CANSocket

socket = CANSocket("vcan0")
viewer(socket)
socket.close()
```

For pause type ":pause".
To continue type ":continue".
To close type ":quit" or  "esc".
