from threading import Thread, Event, RLock

from scapy.sendrecv import sniff


class Sniffer(Thread):
    def __init__(self, main_view, sockets: list, **kwargs):
        """
        A sniffer thread is created which adds the packet to the packet view.

        :param main_view: the urwid widget, which contains all the packet widgets
        :type main_view: packetView.PacketView
        :param sockets: opened sockets, on which the sniffer captures packets/frames
        :type sockets: list
        """

        self.kwargs = kwargs
        self.main_window = main_view
        self.packet_list_view, _ = main_view.body.contents[0]
        self.draw_lock: RLock = self.packet_list_view.draw_lock
        self.sockets = sockets
        Thread.__init__(self)
        self._stopped: Event = Event()  # thread-proof variable

    def add_packet(self, packet):
        """
        Adds a packet to the packet_view_list.

        :param packet: packet sniffed on the interface
        :type packet: Packet
        :return: None
        """
        with self.draw_lock:
            self.packet_list_view.add_packet(packet)

    def run(self):
        """
        Specifies, which tasks the thread will execute.
        """

        while not self._stopped.is_set():
            sniff(opened_socket=self.sockets, timeout=0.1, store=False, prn=self.add_packet, **self.kwargs)

    def stop(self):
        """
        Stops the thread.
        """
        self._stopped.set()
