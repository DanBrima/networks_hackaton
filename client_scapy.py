import socket
import threading
import time
from datetime import datetime

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


class SpeedTestClient:
    def __init__(self):
        print("\033[92mClient started, listening for offer requests...\033[0m")

    def start(self):
        while True:
            try:
                # Get user input for test parameters
                file_size = int(
                    input("\033[96mEnter file size (in bytes): \033[0m"))
                tcp_connections = int(
                    input("\033[96mEnter number of TCP connections: \033[0m"))
                udp_connections = int(
                    input("\033[96mEnter number of UDP connections: \033[0m"))

                if file_size <= 0 or tcp_connections < 0 or udp_connections < 0:
                    raise ValueError("Values must be positive")

            except ValueError as e:
                print(f"\033[91mInvalid input: {e}. Please try again.\033[0m")
                continue

            self._run_speed_test(file_size, tcp_connections, udp_connections)

    def _run_speed_test(self, file_size, tcp_connections, udp_connections):
        """Runs a complete speed test cycle"""
        while True:
            try:
                # Wait for server offer
                print(1)
                server_ip, udp_port, tcp_port = self._wait_for_offer()
                print(server_ip, udp_port, tcp_port)
                # Create and start transfer threads
                threads = []

                # TCP transfers
                for i in range(tcp_connections):
                    thread = threading.Thread(
                        target=self._tcp_transfer,
                        args=(server_ip, tcp_port, file_size, i+1)
                    )
                    threads.append(thread)

                # UDP transfers
                for i in range(udp_connections):
                    thread = threading.Thread(
                        target=self._udp_transfer,
                        args=(server_ip, udp_port, file_size, i+1)
                    )
                    threads.append(thread)

                # Start all transfers
                for thread in threads:
                    thread.start()

                # Wait for all transfers to complete
                for thread in threads:
                    thread.join()

                print(
                    "\033[92mAll transfers complete, listening to offer requests\033[0m")
                break

            except Exception as e:
                print(f"\033[91mError during speed test: {
                      e}. Retrying...\033[0m")
                time.sleep(1)

    def _wait_for_offer(self):
        """Waits for and processes server offer messages using Scapy's sniff"""
        offer_event = threading.Event()
        offer_data = []

        def process_packet(pkt):
            if UDP in pkt and pkt[UDP].dport == 13117:
                try:
                    offer = OfferPacket(bytes(pkt[UDP].payload))
                    if offer.magic_cookie != self.MAGIC_COOKIE:
                        print(
                            "\033[91mInvalid magic cookie, ignoring offer\033[0m")
                        return

                    if offer.msg_type != self.OFFER_MESSAGE_TYPE:
                        print(
                            "\033[91mInvalid message type, ignoring offer\033[0m")
                        return

                    server_ip = pkt[IP].src
                    print(f"\033[93mReceived offer from {
                          server_ip}\033[0m")
                    offer_data.extend(
                        [server_ip, offer.udp_port, offer.tcp_port])
                    offer_event.set()

                    return True
                except:
                    pass

        while not offer_event.is_set():
            sniff(filter="udp and port 13117",
                  prn=process_packet, count=1, timeout=1)

        return tuple(offer_data)

    def _tcp_transfer(self, server_ip, port, file_size, transfer_num):
        """Handles a single TCP transfer"""
        try:
            # Connect to server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, port))

            # Send file size request
            sock.send(f"{file_size}\n".encode())

            # Receive data
            start_time = datetime.now()
            received = 0

            while received < file_size:
                chunk = sock.recv(8192)  # 8KB chunks

                if not chunk:
                    break

                received += len(chunk)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            speed = (file_size * 8) / duration

            print(f"\033[94mTCP transfer #{transfer_num} finished, "
                  f"total time: {duration:.2f} seconds, "
                  f"total speed: {speed:.1f} bits/second\033[0m")

        except Exception as e:
            print(f"\033[91mError in TCP transfer #{transfer_num}: {e}\033[0m")
        finally:
            sock.close()

    def _udp_transfer(self, server_ip, port, file_size, transfer_num):
        """Handles a single UDP transfer using Scapy"""
        try:
            # Send request packet
            request = (IP(dst=server_ip) /
                       UDP(dport=port) /
                       RequestPacket(file_size=file_size))

            send(request, verbose=False)

            # Receive data
            start_time = datetime.now()
            received_segments = set()
            total_segments = None
            last_receive_time = time.time()

            # Setup listener for incoming UDP packets
            def process_packet(pkt):
                nonlocal total_segments, last_receive_time
                # if UDP in pkt and pkt[UDP].dport == request[UDP].sport:
                if True:
                    try:
                        payload = PayloadPacket(bytes(pkt[UDP].payload))
                        if payload.magic_cookie != self.MAGIC_COOKIE:
                            print(
                                "\033[91mInvalid magic cookie, ignoring offer\033[0m")
                            return

                        if payload.msg_type != self.PAYLOAD_MESSAGE_TYPE:
                            print(
                                "\033[91mInvalid message type, ignoring offer\033[0m")
                            return

                        total_segments = payload.total_segments
                        received_segments.add(payload.current_segment)
                        last_receive_time = time.time()
                    except:
                        pass

            # Sniff packets until timeout
            while True:
                sniff(
                    filter=f"udp and port {request[UDP].sport}",
                    prn=process_packet,
                    timeout=1
                )

                if time.time() - last_receive_time >= 1.0:
                    break

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            speed = (file_size * 8) / duration

            if total_segments:
                success_rate = (len(received_segments) / total_segments) * 100
            else:
                success_rate = 0

            print(f"\033[94mUDP transfer #{transfer_num} finished, "
                  f"total time: {duration:.2f} seconds, "
                  f"total speed: {speed:.1f} bits/second, "
                  f"percentage of packets received successfully: {success_rate:.1f}%\033[0m")

        except Exception as e:
            print(f"\033[91mError in UDP transfer #{transfer_num}: {e}\033[0m")


if __name__ == "__main__":
    client = SpeedTestClient()
    try:
        client.start()
    except KeyboardInterrupt:
        print("\033[93mClient shutting down...\033[0m")
