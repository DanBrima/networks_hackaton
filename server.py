import math
import random
import socket
import struct
import threading
import time


class SpeedTestServer:
    CHUNK_SIZE = 8192  # 8KB chunks
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
    BROADCAST_PORT = 13117

    def __init__(self):
        # Initialize server sockets
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind to random available ports
        self.tcp_socket.bind(('', 0))
        self.udp_socket.bind(('', 0))

        # Get the assigned ports
        self.tcp_port = self.tcp_socket.getsockname()[1]
        self.udp_port = self.udp_socket.getsockname()[1]

        # Get server IP
        self.server_ip = socket.gethostbyname(socket.gethostname())

        # Start listening on TCP socket, listen queue size is 100
        self.tcp_socket.listen(100)

        print(f"\033[92mServer started, listening on IP address {
              self.server_ip}. TCP port: {self.tcp_port} UDP port: {self.udp_port}\033[0m")

    def start(self):
        # Start the offer broadcast thread
        offer_thread = threading.Thread(
            target=self._broadcast_offers, daemon=True)
        offer_thread.start()

        # Start accepting TCP connections
        tcp_thread = threading.Thread(
            target=self._handle_tcp_connections, daemon=True)
        tcp_thread.start()

        # Start handling UDP requests
        udp_thread = threading.Thread(
            target=self._handle_udp_requests, daemon=True)
        udp_thread.start()

        # Keep main thread alive
        while True:
            time.sleep(1)

    def _broadcast_offers(self):
        """Broadcasts offer messages every second"""
        broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        while True:
            try:
                # Create offer message
                offer_message = struct.pack(self.OFFER_MESSAGE_FORMAT,
                                            self.MAGIC_COOKIE,
                                            self.OFFER_MESSAGE_TYPE,
                                            self.udp_port,
                                            self.tcp_port
                                            )

                # Broadcast the offer
                broadcast_socket.sendto(
                    offer_message, ('<broadcast>', self.BROADCAST_PORT))
                print(f"\033[96mOffer sent to broadcast address\033[0m")
                time.sleep(1)

            except Exception as e:
                print(f"\033[91mError broadcasting offer: {e}\033[0m")

    def _handle_tcp_connections(self):
        """Accepts and handles TCP connections"""
        while True:
            try:
                client_socket, addr = self.tcp_socket.accept()
                print(f"\033[96mAccepted TCP connection from {addr}\033[0m")
                client_thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_socket, addr), daemon=True
                )
                client_thread.start()

            except Exception as e:
                print(f"\033[91mError accepting TCP connection: {e}\033[0m")

    def _handle_tcp_client(self, client_socket, addr):
        """Handles individual TCP client connections"""
        try:
            # Receive file size request
            file_size = int(client_socket.recv(1024).decode().strip())
            # Generate and send random data
            remaining_size = file_size
            print(f"\033[96mSending {file_size} bytes to TCP {addr}\033[0m")

            while remaining_size > 0:
                send_size = min(self.CHUNK_SIZE, remaining_size)
                data = bytes([random.randint(0, 255)
                             for _ in range(send_size)])
                client_socket.send(data)
                remaining_size -= send_size

        except Exception as e:
            print(f"\033[91mError handling TCP client {addr}: {e}\033[0m")
        finally:
            print(f"\033[96mDone sending. Closing TCP connection to {
                  addr}\033[0m")
            client_socket.close()

    def _handle_udp_requests(self):
        """Handles UDP requests"""
        while True:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
                print(f"\033[96mReceived UDP request from {addr}\033[0m")

                # Verify magic cookie and message type
                magic_cookie, msg_type, file_size = struct.unpack(
                    self.REQUEST_MESSAGE_FORMAT, data)

                if magic_cookie != self.MAGIC_COOKIE:
                    print(
                        "\033[91mInvalid magic cookie, ignoring request\033[0m")
                    continue

                if msg_type != self.REQUEST_MESSAGE_TYPE:
                    print(
                        "\033[91mInvalid message type, ignoring request\033[0m")
                    continue

                # Start new thread for handling UDP transfer
                udp_thread = threading.Thread(
                    target=self._handle_udp_transfer,
                    args=(addr, file_size), daemon=True
                )
                udp_thread.start()

            except Exception as e:
                print(f"\033[91mError handling UDP request: {e}\033[0m")

    def _handle_udp_transfer(self, addr, file_size):
        """Handles individual UDP file transfers"""
        try:
            print(f"\033[96mSending {file_size} bytes to UDP {addr}\033[0m")
            total_segments = math.ceil(file_size / self.CHUNK_SIZE)
            print("total_segments", total_segments)
            for segment in range(total_segments):
                # Calculate remaining bytes
                remaining = file_size - (segment * self.CHUNK_SIZE)
                current_chunk_size = min(self.CHUNK_SIZE, remaining)

                # Create payload
                header = struct.pack(self.PAYLOAD_MESSAGE_FORMAT,
                                     self.MAGIC_COOKIE,
                                     self.PAYLOAD_MESSAGE_TYPE,
                                     total_segments,
                                     segment
                                     )

                payload = bytes([random.randint(0, 255)
                                for _ in range(current_chunk_size)])
                packet = header + payload

                self.udp_socket.sendto(packet, addr)

            print(f"\033[96mDone sending UDP to {
                  addr}\033[0m")
        except Exception as e:
            print(f"\033[91mError handling UDP transfer to {addr}: {e}\033[0m")


if __name__ == "__main__":
    server = SpeedTestServer()

    try:
        server.start()
    except KeyboardInterrupt:
        print("\033[93mServer shutting down...\033[0m")
