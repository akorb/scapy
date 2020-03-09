# Usage

```bash
# Install requirements
$ pip install -r requirements.txt
$ git clone https://github.com/secdev/scapy.git
$ cd scapy
$ python3 setup.py install
```

Der Viewer sollte über ein Python Skript gestartet werde. Zum Beispiel:
```python
from main import viewer

from scapy.contrib.cansocket_native import CANSocket

socket = CANSocket("vcan0")
viewer(socket)
socket.close()
```

Zum Pausieren: ":pause" tippen.
Zum Fortfahren: ":continue" tippen.
Zum Beenden des Programs: ":quit" oder "esc"
