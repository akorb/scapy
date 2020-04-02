# Usage


Start viewer with Python Script.
```python
from scapy.tools.packet_viewer.viewer import viewer

from scapy.contrib.cansocket_native import CANSocket

socket = CANSocket("vcan0")
viewer(socket)
socket.close()
```

For pause type ":pause", ":p", or ":pau" and so on.
To continue type ":continue", ":c", "contin" and so on.
To close type ":quit", ":q", "qui" and so on or  "esc".
