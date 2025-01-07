import socket
import struct
import threading
import time
from datetime import datetime


class SpeedTestClient:
    CHUNK_SIZE = 8192
    MAGIC_COOKIE = 0xabcddcba
    OFFER_MESSAGE_TYPE = 0x2
    REQUEST_MESSAGE_TYPE = 0x3
    PAYLOAD_MESSAGE_TYPE = 0x4
    # Format: magic cookie, message type, UDP port, TCP port
    # The '!' character in the format string indicates network byte order (big-endian)
    # I = unsigned int, b = signed char, H = unsigned short, Q = unsigned long long
    # Whats important is the client reads the data in the same format
    OFFER_MESSAGE_FORMAT = '!IbHH'
    REQUEST_MESSAGE_FORMAT = '!IbQ'
    PAYLOAD_MESSAGE_FORMAT = '!IbQQ'

    def __init__(self):
        # Create UDP socket for receiving offers
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.udp_socket.bind(('', 13117))

        print("\033[92mClient started, listening for offer requests...\033[0m")

    def start(self):
        while True:
            # Get user input for test parameters
            try:
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
        try:
            # Wait for server offer
            server_ip, udp_port, tcp_port = self._wait_for_offer()

            # Create and start transfer threads
            threads = []

            # UDP transfers
            for i in range(udp_connections):
                thread = threading.Thread(
                    target=self._udp_transfer,
                    args=(server_ip, udp_port, file_size, i+1)
                )
                threads.append(thread)

            # TCP transfers
            for i in range(tcp_connections):
                thread = threading.Thread(
                    target=self._tcp_transfer,
                    args=(server_ip, tcp_port, file_size, i+1)
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

        except Exception as e:
            print(f"\033[91mError during speed test: {
                e}. Retrying...\033[0m")
            time.sleep(1)

    def _wait_for_offer(self):
        """Waits for and processes server offer messages"""
        while True:
            try:
                data, addr = self.udp_socket.recvfrom(1024)

                # Unpack offer message
                magic_cookie, msg_type, udp_port, tcp_port = struct.unpack(
                    self.OFFER_MESSAGE_FORMAT, data)

                if magic_cookie != self.MAGIC_COOKIE:
                    print(
                        "\033[91mInvalid magic cookie, ignoring request\033[0m")
                    continue

                if msg_type != self.OFFER_MESSAGE_TYPE:
                    print(
                        "\033[91mInvalid message type, ignoring request\033[0m")
                    continue

                server_ip = addr[0]
                print(f"\033[93mReceived offer from {
                      server_ip}:{addr[1]}\033[0m")

                return server_ip, udp_port, tcp_port

            except Exception as e:
                print(f"\033[91mError receiving offer: {e}\033[0m")
                time.sleep(1)

    def _tcp_transfer(self, server_ip, port, file_size, transfer_num):
        """Handles a single TCP transfer"""
        try:
            print("\033[94mStarting TCP transfer...\033[0m")
            # Connect to server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, port))

            # Send file size request
            sock.send(f"{file_size}\n".encode())

            # Receive data
            start_time = datetime.now()
            received = 0

            while received < file_size:
                chunk = sock.recv(self.CHUNK_SIZE)
                if not chunk:
                    break

                received += len(chunk)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            speed = (file_size * 8) / duration  # bits per second

            print(f"\033[94mTCP transfer #{transfer_num} finished, "
                  f"total time: {duration:.2f} seconds, "
                  f"total speed: {speed:.1f} bits/second\033[0m")

        except Exception as e:
            print(f"\033[91mError in TCP transfer #{transfer_num}: {e}\033[0m")
        finally:
            sock.close()

    def _udp_transfer(self, server_ip, port, file_size, transfer_num):
        """Handles a single UDP transfer"""
        try:
            print("\033[94mStarting UDP transfer...\033[0m")
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)  # 1 second timeout

            # Send request
            request = struct.pack(self.REQUEST_MESSAGE_FORMAT,
                                  self.MAGIC_COOKIE,
                                  self.REQUEST_MESSAGE_TYPE,
                                  file_size
                                  )
            sock.sendto(request, (server_ip, port))

            # Receive data
            start_time = datetime.now()
            received_segments = set()
            total_segments = None

            while True:
                try:
                    data, _ = sock.recvfrom(self.CHUNK_SIZE)

                    # Unpack header
                    header_size = struct.calcsize(self.PAYLOAD_MESSAGE_FORMAT)
                    header = data[:header_size]
                    magic_cookie, msg_type, total_segs, current_seg = struct.unpack(
                        self.PAYLOAD_MESSAGE_FORMAT, header)

                    if magic_cookie != self.MAGIC_COOKIE:
                        print(
                            "\033[91mInvalid magic cookie, ignoring request\033[0m")
                        continue

                    if msg_type != self.PAYLOAD_MESSAGE_TYPE:
                        print(
                            "\033[91mInvalid message type, ignoring request\033[0m")
                        continue

                    total_segments = total_segs
                    received_segments.add(current_seg)
# quesrions:
#     data formatting - should use palyload on both?
#     UDP timeout is not fair
                except socket.timeout:
                    print("\033[93mUDP connection Timeout...\033[0m")
                    break

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            speed = (file_size * 8) / duration  # bits per second

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
        finally:
            sock.close()


if __name__ == "__main__":
    client = SpeedTestClient()
    try:
        client.start()
    except KeyboardInterrupt:
        print("\033[93mClient shutting down...\033[0m")
