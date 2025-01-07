import math
import random
import socket
import threading
import time

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.fields import ByteField, IntField, LongField, ShortField, StrField
from scapy.layers.inet import IP, UDP, Ether, bind_layers
from scapy.packet import Packet
from scapy.sendrecv import send, sendp, sniff

MAGIC_COOKIE = 0xabcddcba
OFFER_MESSAGE_TYPE = 0x2
REQUEST_MESSAGE_TYPE = 0x3
PAYLOAD_MESSAGE_TYPE = 0x4

# Define custom packet formats


class OfferPacket(Packet):
    name = "SpeedTestOffer"
    fields_desc = [
        IntField("magic_cookie", MAGIC_COOKIE),
        ByteField("msg_type", OFFER_MESSAGE_TYPE),
        ShortField("udp_port", 0),
        ShortField("tcp_port", 0)
    ]


class RequestPacket(Packet):
    name = "SpeedTestRequest"
    fields_desc = [
        IntField("magic_cookie", MAGIC_COOKIE),
        ByteField("msg_type", REQUEST_MESSAGE_TYPE),
        LongField("file_size", 0)
    ]


class PayloadPacket(Packet):
    name = "SpeedTestPayload"
    fields_desc = [
        IntField("magic_cookie", MAGIC_COOKIE),
        ByteField("msg_type", 0x4),
        LongField("total_segments", 0),
        LongField("current_segment", 0),
        StrField("payload", "")
    ]


# Register custom packet formats
bind_layers(UDP, OfferPacket)
bind_layers(UDP, RequestPacket)
bind_layers(UDP, PayloadPacket)


class SpeedTestServer:
    def __init__(self):
        # Create TCP and UDP sockets using Scapy
        self.tcp_port = random.randint(10000, 65535)
        self.udp_port = random.randint(10000, 65535)

        # Get server IP
        self.server_ip = get_if_addr(conf.iface)

        print(f"\033[92mServer started, listening on IP address {
              self.server_ip}\033[0m")

    def start(self):
        # Start the offer broadcast thread
        offer_thread = threading.Thread(
            target=self._broadcast_offers, daemon=True)
        offer_thread.start()

        # Start UDP listener
        udp_thread = threading.Thread(
            target=self._handle_udp_requests, daemon=True)
        udp_thread.start()

        # Start TCP listener
        tcp_thread = threading.Thread(
            target=self._handle_tcp_connections, daemon=True)
        tcp_thread.start()

        # Keep main thread alive, finish when all threads are done
        offer_thread.join()
        udp_thread.join()
        tcp_thread.join()

    def _broadcast_offers(self):
        """Broadcasts offer messages every second"""
        while True:
            try:
                # Create and send offer packet
                offer = (Ether() / IP(dst="255.255.255.255") /
                         UDP(sport=self.udp_port, dport=13117) /
                         OfferPacket(
                    udp_port=self.udp_port,
                    tcp_port=self.tcp_port
                ))

                sendp(offer, verbose=False)
                print(f"\033[96mOffer sent to broadcast address\033[0m")

            except Exception as e:
                print(f"\033[91mError broadcasting offer: {e}\033[0m")
            finally:
                time.sleep(1)

    def _handle_tcp_connections(self):
        """Handles TCP connections using Scapy"""
        # Create TCP listener
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', self.tcp_port))
        sock.listen(5)  # Have up to 5 waiting connections

        while True:
            try:
                client_sock, addr = sock.accept()
                print(f"\033[96mAccepted TCP connection from {addr}\033[0m")

                client_thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_sock, addr), daemon=True
                )
                client_thread.start()

            except Exception as e:
                print(f"\033[91mError accepting TCP connection: {e}\033[0m")

    def _handle_tcp_client(self, client_sock, addr):
        """Handles individual TCP client connections"""
        try:
            # Receive file size request
            file_size = int(client_sock.recv(1024).decode().strip())
            print(f"\033[96mSending {file_size} bytes to {addr}\033[0m")

            # Generate and send random data
            remaining_size = file_size
            chunk_size = 8192  # 8KB chunks

            while remaining_size > 0:
                send_size = min(chunk_size, remaining_size)
                data = bytes([random.randint(0, 255)
                             for _ in range(send_size)])
                client_sock.send(data)
                remaining_size -= send_size

        except Exception as e:
            print(f"\033[91mError handling TCP client {addr}: {e}\033[0m")
        finally:
            print(f"\033[96mDone sending. Closing connection to {addr}\033[0m")
            client_sock.close()

    def _handle_udp_requests(self):
        """Handles UDP requests using Scapy's sniff function"""
        if True:
            def process_packet(pkt):
                if UDP in pkt and pkt[UDP].dport == self.udp_port:
                    try:
                        # Extract data from packet
                        data = bytes(pkt[UDP].payload)
                        # if len(data) < 13:  # Minimum size for request packet
                        #     print(
                        #         "\033[91mInvalid request packet, ignoring\033[0m")
                        #     return

                        # Parse request packet
                        request = RequestPacket(data)

                        if request.magic_cookie != MAGIC_COOKIE:
                            print(
                                "\033[91mInvalid magic cookie, ignoring request\033[0m")
                            return

                        if request.msg_type != REQUEST_MESSAGE_TYPE:
                            print(
                                "\033[91mInvalid message type, ignoring request\033[0m")
                            return

                        addr = (pkt[IP].src, pkt[UDP].sport)
                        print(f"\033[96mReceived UDP request from {
                              addr}\033[0m")

                        # Start new thread for handling UDP transfer
                        udp_thread = threading.Thread(
                            target=self._handle_udp_transfer,
                            args=(addr, request.file_size), daemon=True
                        )
                        udp_thread.start()

                    except Exception as e:
                        print(
                            f"\033[91mError processing UDP request: {e}\033[0m")

        # Start sniffing for UDP packets
        sniff(filter=f"udp and port {self.udp_port}", prn=process_packet)

    def _handle_udp_transfer(self, addr, file_size):
        """Handles individual UDP file transfers"""
        try:
            chunk_size = 1024  # 1KB chunks
            total_segments = math.ceil(file_size / chunk_size)

            for segment in range(total_segments):
                remaining = file_size - (segment * chunk_size)
                current_chunk_size = min(chunk_size, remaining)
                payload = bytes([random.randint(0, 255)
                                for _ in range(current_chunk_size)])

                # Create and send packet
                pkt = (IP(dst=addr[0]) /
                       UDP(sport=self.udp_port, dport=addr[1]) /
                       PayloadPacket(
                    total_segments=total_segments,
                    current_segment=segment,
                    payload=payload
                ))

                send(pkt, verbose=False)
                # time.sleep(0.001)

        except Exception as e:
            print(f"\033[91mError handling UDP transfer to {addr}: {e}\033[0m")


if __name__ == "__main__":
    server = SpeedTestServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\033[93mServer shutting down...\033[0m")
