#!/usr/bin/env python3
"""
WriteLog to QLog UDP Converter
Listens for WriteLog XML broadcasts on UDP 2236
Converts to WSJT-X ADIF format and rebroadcasts on UDP 2237
Author: Steve Woodruff, N9OH <steve@n9oh.com>
"""

import socket
import struct
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Optional

# Configuration
WRITELOG_PORT = 2236  # WriteLog broadcasts to this port (configure WriteLog to use 2236)
QLOG_PORT = 2237      # QLog listens on this port
LISTEN_IP = '0.0.0.0'
BROADCAST_IP = '127.0.0.1'
SOURCE_PORT = 52946   # Match WSJT-X source port

# WSJT-X binary protocol constants
MAGIC = 0xadbccbda
SCHEMA = 2
MSG_TYPE_HEARTBEAT = 0
MSG_TYPE_STATUS = 1
MSG_TYPE_QSO_LOGGED = 5
MSG_TYPE_ADIF = 12


class WSJTXPacketBuilder:
    """Builds WSJT-X binary protocol packets"""

    @staticmethod
    def encode_string(s: str) -> bytes:
        """Encode a length-prefixed UTF-8 string"""
        if s is None:
            s = ""
        encoded = s.encode('utf-8')
        return struct.pack('>I', len(encoded)) + encoded

    @staticmethod
    def encode_bool(b: bool) -> bytes:
        """Encode a boolean"""
        return struct.pack('?', b)

    @staticmethod
    def encode_int32(i: int) -> bytes:
        """Encode a 32-bit integer"""
        return struct.pack('>i', i)

    @staticmethod
    def encode_uint32(i: int) -> bytes:
        """Encode a 32-bit unsigned integer"""
        return struct.pack('>I', i)

    @staticmethod
    def encode_uint64(i: int) -> bytes:
        """Encode a 64-bit unsigned integer"""
        return struct.pack('>Q', i)

    def build_header(self, msg_type: int) -> bytes:
        """Build packet header"""
        return (struct.pack('>I', MAGIC) +
                struct.pack('>I', SCHEMA) +
                struct.pack('>I', msg_type))

    def build_heartbeat(self) -> bytes:
        """Build heartbeat packet (type 0)"""
        packet = self.build_header(MSG_TYPE_HEARTBEAT)
        packet += self.encode_string("WSJT-X")
        packet += self.encode_uint32(3)  # Max schema
        packet += self.encode_string("2.7.0")  # Version
        packet += self.encode_string("b4f9a4")  # Revision
        return packet

    def build_status(self, qso_data: Dict) -> bytes:
        """Build status packet (type 1)"""
        packet = self.build_header(MSG_TYPE_STATUS)
        packet += self.encode_string("WSJT-X")

        # Frequency in Hz
        freq_hz = int(qso_data.get('freq_hz', 0))
        packet += self.encode_uint64(freq_hz)

        # Mode
        packet += self.encode_string(qso_data.get('mode', ''))

        # DX call
        packet += self.encode_string(qso_data.get('call', ''))

        # Report (rst sent)
        packet += self.encode_string(qso_data.get('rst_sent', ''))

        # TX mode
        packet += self.encode_string(qso_data.get('mode', ''))

        # TX enabled
        packet += self.encode_bool(False)

        # Transmitting
        packet += self.encode_bool(False)

        # Decoding
        packet += self.encode_bool(False)

        # RX DF (frequency offset)
        packet += self.encode_uint32(1500)

        # TX DF
        packet += self.encode_uint32(1500)

        # DE call (my call)
        packet += self.encode_string(qso_data.get('station_call', ''))

        # DE grid (my grid)
        packet += self.encode_string(qso_data.get('my_grid', ''))

        # DX grid
        packet += self.encode_string(qso_data.get('dx_grid', ''))

        # TX watchdog
        packet += self.encode_bool(False)

        # Sub-mode
        packet += self.encode_string("")

        # Fast mode
        packet += self.encode_bool(False)

        # Special op mode
        packet += struct.pack('B', 0)

        # Frequency tolerance
        packet += self.encode_uint32(0xffffffff)

        # T/R period
        packet += self.encode_uint32(0xffffffff)

        # Configuration name
        packet += self.encode_string("Default")

        # TX message (use -1 for unspecified)
        packet += self.encode_int32(-1)

        return packet

    def build_qso_logged(self, qso_data: Dict) -> bytes:
        """Build QSO logged packet (type 5)"""
        packet = self.build_header(MSG_TYPE_QSO_LOGGED)
        packet += self.encode_string("WSJT-X")

        # Date-time off (milliseconds since epoch)
        timestamp = qso_data.get('timestamp_ms', int(time.time() * 1000))
        packet += self.encode_uint64(timestamp)

        # DX call
        packet += self.encode_string(qso_data.get('call', ''))

        # DX grid
        packet += self.encode_string(qso_data.get('dx_grid', ''))

        # Frequency in Hz
        freq_hz = int(qso_data.get('freq_hz', 0))
        packet += self.encode_uint64(freq_hz)

        # Mode
        packet += self.encode_string(qso_data.get('mode', ''))

        # Report sent
        packet += self.encode_string(qso_data.get('rst_sent', ''))

        # Report received
        packet += self.encode_string(qso_data.get('rst_rcvd', ''))

        # TX power
        packet += self.encode_string("")

        # Comments
        packet += self.encode_string("")

        # Name
        packet += self.encode_string("")

        # Date-time on
        packet += self.encode_uint64(timestamp)

        # Operator call
        packet += self.encode_string("")

        # My call
        packet += self.encode_string(qso_data.get('station_call', ''))

        # My grid
        packet += self.encode_string(qso_data.get('my_grid', ''))

        # Exchange sent
        packet += self.encode_string("")

        # Exchange received
        packet += self.encode_string("")

        # ADIF propagation mode (use -1 for unspecified)
        packet += self.encode_int32(-1)

        return packet

    def build_adif(self, adif_text: str) -> bytes:
        """Build ADIF packet (type 12)"""
        packet = self.build_header(MSG_TYPE_ADIF)
        packet += self.encode_string("WSJT-X")
        packet += self.encode_string(adif_text)
        return packet


class WriteLogConverter:
    """Converts WriteLog XML to WSJT-X ADIF format"""

    def __init__(self):
        self.packet_builder = WSJTXPacketBuilder()

    def parse_writelog_xml(self, xml_data: str) -> Optional[Dict]:
        """Parse WriteLog XML packet"""
        try:
            root = ET.fromstring(xml_data)

            # Extract QSO data
            qso = {}
            for elem in root:
                qso[elem.tag] = elem.text if elem.text else ""

            return qso
        except Exception as e:
            print(f"Error parsing XML: {e}")
            return None

    def convert_frequency(self, txfreq: str) -> tuple:
        """Convert WriteLog frequency to MHz and determine band"""
        try:
            # WriteLog sends frequency in 10 Hz units (decihertz), so multiply by 10
            freq_hz = int(txfreq) * 10
            freq_mhz = freq_hz / 1_000_000

            # Determine band
            if 1800000 <= freq_hz < 2000000:
                band = "160m"
            elif 3500000 <= freq_hz < 4000000:
                band = "80m"
            elif 5330000 <= freq_hz < 5405000:
                band = "60m"
            elif 7000000 <= freq_hz < 7300000:
                band = "40m"
            elif 10100000 <= freq_hz < 10150000:
                band = "30m"
            elif 14000000 <= freq_hz < 14350000:
                band = "20m"
            elif 18068000 <= freq_hz < 18168000:
                band = "17m"
            elif 21000000 <= freq_hz < 21450000:
                band = "15m"
            elif 24890000 <= freq_hz < 24990000:
                band = "12m"
            elif 28000000 <= freq_hz < 29700000:
                band = "10m"
            elif 50000000 <= freq_hz < 54000000:
                band = "6m"
            elif 144000000 <= freq_hz < 148000000:
                band = "2m"
            else:
                band = f"{int(freq_mhz)}m"

            return freq_hz, freq_mhz, band
        except:
            return 0, 0.0, ""

    def convert_timestamp(self, timestamp: str) -> tuple:
        """Convert WriteLog timestamp to ADIF format"""
        try:
            # Parse timestamp: "2022-11-05 21:17:57"
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            qso_date = dt.strftime("%Y%m%d")
            time_on = dt.strftime("%H%M%S")
            timestamp_ms = int(dt.timestamp() * 1000)
            return qso_date, time_on, timestamp_ms
        except:
            now = datetime.utcnow()
            return now.strftime("%Y%m%d"), now.strftime("%H%M%S"), int(time.time() * 1000)

    def normalize_mode(self, mode: str) -> str:
        """Normalize mode name for ADIF"""
        mode = mode.upper()
        mode_map = {
            'SSB': 'USB',
            'LSB': 'LSB',
            'USB': 'USB',
            'CW': 'CW',
            'RTTY': 'RTTY',
            'PSK': 'PSK31',
            'FT8': 'FT8',
            'FT4': 'FT4',
            'JT65': 'JT65',
            'JT9': 'JT9',
        }
        return mode_map.get(mode, mode)

    def build_adif_text(self, qso: Dict, qso_data: Dict) -> str:
        """Build ADIF text record"""
        # Header
        adif_text = "<adif_ver:5>3.1.0\n<programid:6>WSJT-X\n<EOH>\n"

        # All QSO fields on one line separated by spaces
        fields = []

        # Required fields
        call = qso.get('call', '').upper()
        fields.append(f"<call:{len(call)}>{call}")

        # Grid square (include even if placeholder AA00)
        dx_grid = qso_data.get('dx_grid', '')
        if dx_grid:
            fields.append(f"<gridsquare:{len(dx_grid)}>{dx_grid}")

        # Mode
        mode = qso_data.get('mode', '')
        if mode:
            fields.append(f"<mode:{len(mode)}>{mode}")

        # RST
        rst_sent = qso_data.get('rst_sent', '')
        if rst_sent:
            fields.append(f"<rst_sent:{len(rst_sent)}>{rst_sent}")

        rst_rcvd = qso_data.get('rst_rcvd', '')
        if rst_rcvd:
            fields.append(f"<rst_rcvd:{len(rst_rcvd)}>{rst_rcvd}")

        # Date/Time
        qso_date = qso_data.get('qso_date', '')
        if qso_date:
            fields.append(f"<qso_date:{len(qso_date)}>{qso_date}")

        time_on = qso_data.get('time_on', '')
        if time_on:
            fields.append(f"<time_on:{len(time_on)}>{time_on}")
            fields.append(f"<qso_date_off:{len(qso_date)}>{qso_date}")
            fields.append(f"<time_off:{len(time_on)}>{time_on}")

        # Band
        band = qso_data.get('band', '')
        if band:
            fields.append(f"<band:{len(band)}>{band}")

        # Frequency
        freq_str = f"{qso_data.get('freq_mhz', 0):.6f}"
        fields.append(f"<freq:{len(freq_str)}>{freq_str}")

        # Station info
        station_call = qso_data.get('station_call', '')
        if station_call:
            fields.append(f"<station_callsign:{len(station_call)}>{station_call}")

        my_grid = qso_data.get('my_grid', '')
        if my_grid:
            fields.append(f"<my_gridsquare:{len(my_grid)}>{my_grid}")

        fields.append("<EOR>")

        # Join all fields with spaces on one line
        adif_text += " ".join(fields) + "\n"

        return adif_text

    def convert(self, xml_data: str) -> Optional[list]:
        """Convert WriteLog XML to WSJT-X packets"""
        qso = self.parse_writelog_xml(xml_data)
        if not qso:
            return None

        # Skip if not a new QSO
        if qso.get('newqso', '').lower() != 'true':
            return None

        # Build QSO data dict
        qso_data = {}

        # Call
        qso_data['call'] = qso.get('call', '').upper()
        qso_data['station_call'] = qso.get('mycall', '').upper()

        # Frequency and band
        freq_hz, freq_mhz, band = self.convert_frequency(qso.get('txfreq', '0'))
        qso_data['freq_hz'] = freq_hz
        qso_data['freq_mhz'] = freq_mhz
        qso_data['band'] = band

        # Mode
        qso_data['mode'] = self.normalize_mode(qso.get('mode', 'CW'))

        # RST
        qso_data['rst_sent'] = qso.get('snt', '599')
        qso_data['rst_rcvd'] = qso.get('rcv', '599')

        # Grid square (try to extract from exchange fields)
        # Many contests put grid in exch fields
        dx_grid = ""
        for i in range(1, 5):
            exch = qso.get(f'exch{i}', '').upper()
            # Check if it looks like a grid square (e.g., DN55, EL96)
            if len(exch) == 4 and exch[:2].isalpha() and exch[2:].isdigit():
                dx_grid = exch
                break

        # If no grid found, use placeholder to trigger QLog's QRZ lookup
        #
        # QLog Behavior Analysis (from source code examination):
        # - CallbookManager only needs callsign (≥3 chars) for QRZ lookup
        # - NewContactWidget triggers lookup via finalizeCallsignEdit() when user presses Tab/Enter
        # - WSJT-X Status packets populate fields via prepareWSJTXQSO() but may not call finalization
        # - Testing confirmed: empty DX grid = no lookup; any grid value = lookup triggered
        #
        # Why AA00?
        # - Triggers QLog to call CallbookManager.queryCallsign() and fetch name/QTH from QRZ
        # - QLog will save AA00 as the grid (not ideal, but acceptable tradeoff)
        # - User can bulk-update grids in QLog later if needed (Edit > Replace)
        # - Alternative would be to not auto-log (just show in QLog for manual confirmation)
        #
        if not dx_grid:
            dx_grid = "AA00"  # Minimal placeholder - Atlantic Ocean, triggers QRZ lookup

        qso_data['dx_grid'] = dx_grid
        # Use my grid from WriteLog mycall location, or default to EL96 (adjust for your QTH)
        qso_data['my_grid'] = "EL96"  # TODO: Configure your grid square here

        # Timestamp
        qso_date, time_on, timestamp_ms = self.convert_timestamp(qso.get('timestamp', ''))
        qso_data['qso_date'] = qso_date
        qso_data['time_on'] = time_on
        qso_data['timestamp_ms'] = timestamp_ms

        # Build ADIF text
        adif_text = self.build_adif_text(qso, qso_data)

        # Build all 5 packets (match WSJT-X order)
        packets = []
        packets.append(self.packet_builder.build_heartbeat())      # First
        packets.append(self.packet_builder.build_status(qso_data)) # Triggers lookup
        packets.append(self.packet_builder.build_qso_logged(qso_data))
        packets.append(self.packet_builder.build_adif(adif_text))
        packets.append(self.packet_builder.build_heartbeat())      # Last

        return packets


def dump_packet_to_file(packets: list, filename: str = "wl2qlog.dump.txt"):
    """Dump packets to file in replay2.dump.txt format"""
    with open(filename, 'w') as f:
        for i, packet in enumerate(packets, 1):
            f.write(f"--- Packet {i} ({len(packet)} bytes) ---\n")

            # Write hex dump in groups of 16 bytes
            for offset in range(0, len(packet), 16):
                chunk = packet[offset:offset+16]

                # Offset in hex (4 digits)
                f.write(f"{offset:04x}  ")

                # Hex bytes (2 chars each, space separated)
                hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
                f.write(hex_bytes)

                # Newline
                f.write("\n")

            f.write("\n")
    print(f"Dumped packets to {filename}")


def main():
    """Main UDP listener and broadcaster"""
    print("WriteLog to QLog UDP Converter")
    print(f"Listening for WriteLog on UDP {WRITELOG_PORT}")
    print(f"Broadcasting to QLog on UDP {QLOG_PORT}")
    print()
    print("NOTE: Configure WriteLog to broadcast UDP to port 2236")
    print()

    converter = WriteLogConverter()

    # Create listener socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((LISTEN_IP, WRITELOG_PORT))
    listen_sock.settimeout(1.0)  # 1 second timeout for Ctrl+C handling

    # Create persistent broadcast socket (keep open for all contacts)
    broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    broadcast_sock.bind((BROADCAST_IP, SOURCE_PORT))
    print(f"Broadcast socket bound to {BROADCAST_IP}:{SOURCE_PORT}")

    print("Ready. Waiting for WriteLog packets...")
    print()

    try:
        while True:
            try:
                # Receive WriteLog packet (times out every second)
                data, addr = listen_sock.recvfrom(4096)
            except socket.timeout:
                # Just loop again to check for Ctrl+C
                continue

            # Process received packet
            try:
                xml_data = data.decode('utf-8')
            except UnicodeDecodeError:
                # Ignore binary packets (likely our own WSJT-X broadcasts)
                continue

            try:
                # Check if it's XML
                if not xml_data.strip().startswith('<?xml'):
                    continue

                print(f"Received WriteLog packet from {addr}")
                print(f"WriteLog XML:\n{xml_data}\n")

                # Convert to WSJT-X packets
                packets = converter.convert(xml_data)

                if packets:
                    print(f"Converting and broadcasting {len(packets)} packets...")

                    # Dump packets to file for debugging
                    dump_packet_to_file(packets)

                    # Use persistent broadcast socket
                    # Send packets like WSJT-X does
                    # Packet 0: Heartbeat
                    broadcast_sock.sendto(packets[0], (BROADCAST_IP, QLOG_PORT))
                    print(f"  Sent Heartbeat")
                    time.sleep(0.5)

                    # Send Status packet multiple times (triggers QLog lookup)
                    print(f"  Sending Status packets (triggers QLog lookup)...")
                    for i in range(3):
                        broadcast_sock.sendto(packets[1], (BROADCAST_IP, QLOG_PORT))
                        print(f"    Status packet {i+1}/3")
                        time.sleep(0.2)

                    # Wait for QLog to do lookup
                    print(f"  Waiting 1.5 seconds for QLog to complete lookup...")
                    time.sleep(1.5)

                    # Send final Status packet
                    broadcast_sock.sendto(packets[1], (BROADCAST_IP, QLOG_PORT))
                    print(f"    Final Status packet")
                    time.sleep(0.5)

                    # Now log the QSO
                    broadcast_sock.sendto(packets[2], (BROADCAST_IP, QLOG_PORT))
                    print(f"  Sent QSO Logged")
                    time.sleep(0.01)

                    broadcast_sock.sendto(packets[3], (BROADCAST_IP, QLOG_PORT))
                    print(f"  Sent ADIF")
                    time.sleep(1.0)

                    broadcast_sock.sendto(packets[4], (BROADCAST_IP, QLOG_PORT))
                    print(f"  Sent Heartbeat")

                    print("Done.\n")
                else:
                    print("Skipped (not a new QSO)\n")

            except Exception as e:
                print(f"Error processing packet: {e}\n")
                continue

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        listen_sock.close()
        broadcast_sock.close()


if __name__ == '__main__':
    main()
