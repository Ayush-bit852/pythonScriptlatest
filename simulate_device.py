"""
import socket
import time
import re
import threading
import argparse
import logging
import json
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime

# === SET UP LOGGER ===
logger = logging.getLogger("simulate_device_logger")
logger.setLevel(logging.DEBUG)
logger.propagate = False

if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    file_handler = TimedRotatingFileHandler(
        'script_logs.log', when='midnight', interval=1, backupCount=7, encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

# Load ports and protocol from JSON
def load_ports(file='protocol_ports.json'):
    try:
        with open(file, 'r') as f:
            port_data = json.load(f)
            return {str(v): k for k, v in port_data.items()}
    except Exception as e:
        logger.warning(f"Could not load protocol_ports.json: {e}")
        return {}

PORT_PROTOCOL_MAP = load_ports()

# === MATCHERS ===
matchers = {
    "tcp_hex": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+INFO:\s+\[(?P<session>[a-f0-9]+): (?P<port>\d+) < (?P<ip>[\d\.]+):(?P<client_port>\d+)\] \[TCP\] HEX: (?P<hex>[0-9A-Fa-f]+)"
    ),
}

def parse_line(line):
    for type_, pattern in matchers.items():
        match = pattern.match(line.strip())
        if match:
            data = match.groupdict()
            try:
                data['timestamp'] = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
                data['type'] = type_
                return data
            except ValueError:
                logger.warning(f"Invalid timestamp format: {data.get('timestamp')}")
    return None

def parse_log_file(file_path):
    logger.info(f"Reading: {file_path}")
    parsed = []

    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            parsed_data = parse_line(line)
            if parsed_data:
                parsed.append(parsed_data)
            else:
                logger.debug(f"🔸 Skipping unmatched line {i}")
    return parsed

def simulate_device_traffic(messages, realtime=True):
    grouped = {}
    for msg in messages:
        port = int(msg["port"])
        grouped.setdefault(port, []).append(msg)

    threads = []
    for port, msgs in grouped.items():
        t = threading.Thread(target=simulate_for_port, args=(msgs, port, realtime))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def simulate_for_port(messages, port, realtime):
    protocol = PORT_PROTOCOL_MAP.get(str(port), "unknown")
    logger.info(f"🔌 Connecting to 127.0.0.1:{port} ({protocol})")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
    except Exception as e:
        logger.error(f"❌ Connection to {port} failed: {e}")
        return

    start_time = messages[0]['timestamp']
    sim_start = time.time()

    for msg in messages:
        delay = (msg['timestamp'] - start_time).total_seconds()
        if realtime:
            elapsed = time.time() - sim_start
            sleep_time = delay - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

        hex_data = msg['hex']
        try:
            s.sendall(bytes.fromhex(hex_data))
            logger.info(f"📤 Sent to port {port}: {hex_data}")
        except Exception as e:
            logger.error(f"❌ Failed sending to {port}: {e}")
            break

    s.close()
    logger.info(f"✅ Port {port} simulation complete.")

def main():
    parser = argparse.ArgumentParser(description="TCP Simulator for IoT HEX log files.")
    parser.add_argument("log_file", help="Path to the Traccar log file")
    parser.add_argument("--fast", action="store_true", help="Skip real-time delay")
    args = parser.parse_args()

    all_messages = parse_log_file(args.log_file)
    if all_messages:
        simulate_device_traffic(all_messages, realtime=not args.fast)
    else:
        logger.warning("No valid messages found.")

if __name__ == "__main__":
    main()
"""

import socket
import time
import re
import threading
import argparse
import logging
import json
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
from pathlib import Path
import os

# === SET UP LOGGER ===
logger = logging.getLogger("device_simulator")
logger.setLevel(logging.DEBUG)
logger.propagate = False

if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    file_handler = TimedRotatingFileHandler(
        'simulator.log', when='midnight', interval=1, backupCount=7, encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

# Load ports and protocol from JSON
def load_ports(file='protocol_ports.json'):
    try:
        with open(file, 'r') as f:
            port_data = json.load(f)
            return {str(v): k for k, v in port_data.items()}
    except Exception as e:
        logger.warning(f"Could not load protocol_ports.json: {e}")
        # Default ports if file not found
        return {
            "80": "HTTP",
            "443": "HTTPS",
            "8080": "HTTP-ALT",
            "5005": "TCP-DEFAULT"
        }

# Use raw strings for regex patterns to avoid escape sequence warnings
matchers = {
    "tcp_hex": re.compile(
        r"""(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+INFO:\s+\[(?P<session>[a-f0-9]+):\s+
        (?P<port>\d+)\s+<\s+(?P<ip>[\d\.]+):(?P<client_port>\d+)\]\s+\[(TCP|HTTP)\]\s+(HEX|DATA):\s+
        (?P<data>[0-9A-Fa-f]+)""", re.VERBOSE
    ),
    "http_data": re.compile(
        r"""(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+INFO:\s+\[(?P<session>[a-f0-9]+):\s+
        (?P<port>\d+)\s+<\s+(?P<ip>[\d\.]+):(?P<client_port>\d+)\]\s+\[HTTP\]\s+DATA:\s+
        (?P<data>.+)""", re.VERBOSE
    )
}

def parse_line(line):
    line = line.strip()
    for type_, pattern in matchers.items():
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            try:
                data['timestamp'] = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
                data['type'] = type_
                # Clean up the data field if it contains HEX
                if type_ == 'tcp_hex':
                    data['data'] = data['data'].replace(' ', '')  # Remove spaces from HEX
                return data
            except ValueError as e:
                logger.warning(f"Invalid timestamp format in line: {line}\nError: {e}")
                return None
    logger.debug(f"No match found for line: {line}")
    return None

def parse_log_file(file_path):
    logger.info(f"Reading: {file_path}")
    parsed = []
    line_count = 0
    matched_count = 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_count += 1
                parsed_data = parse_line(line)
                if parsed_data:
                    parsed.append(parsed_data)
                    matched_count += 1
                elif line.strip():  # Only log if line is not empty
                    logger.debug(f"Skipping unmatched line {line_count}: {line.strip()}")
                    
        logger.info(f"Parsed {matched_count}/{line_count} lines successfully")
        return parsed
        
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return []

def simulate_device_traffic(messages, realtime=True):
    if not messages:
        logger.error("No valid messages to simulate")
        return

    grouped = {}
    for msg in messages:
        port = int(msg["port"])
        grouped.setdefault(port, []).append(msg)

    threads = []
    for port, msgs in grouped.items():
        t = threading.Thread(
            target=simulate_port_connection,
            args=(msgs, port, realtime),
            daemon=True
        )
        threads.append(t)
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested...")
    finally:
        logger.info("Simulation stopped")

def simulate_port_connection(messages, port, realtime):
    protocol = PORT_PROTOCOL_MAP.get(str(port), "UNKNOWN")
    logger.info(f"Starting {protocol} connection to 127.0.0.1:{port}")
    
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                try:
                    s.connect(("127.0.0.1", port))
                    logger.info(f"Connected to {port}")
                except ConnectionRefusedError:
                    logger.error(f"Connection refused on port {port}, retrying in 5s...")
                    time.sleep(5)
                    continue
                
                start_time = messages[0]['timestamp']
                sim_start = time.time()
                
                for msg in messages:
                    # Handle timing
                    delay = (msg['timestamp'] - start_time).total_seconds()
                    if realtime:
                        elapsed = time.time() - sim_start
                        sleep_time = delay - elapsed
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                    
                    try:
                        if msg['type'] == 'tcp_hex':
                            # Send raw TCP data
                            data = bytes.fromhex(msg['data'])
                            s.sendall(data)
                            logger.info(f"Sent TCP data to {port}: {msg['data']}")
                            
                        elif msg['type'] == 'http_data':
                            # Send HTTP request
                            http_request = (
                                f"POST / HTTP/1.1\r\n"
                                f"Host: 127.0.0.1:{port}\r\n"
                                f"Content-Type: application/json\r\n"
                                f"Content-Length: {len(msg['data'])}\r\n"
                                f"Connection: keep-alive\r\n"
                                f"\r\n"
                                f"{msg['data']}"
                            )
                            s.sendall(http_request.encode('utf-8'))
                            logger.info(f"Sent HTTP request to {port}")
                            
                            # Get response
                            response = s.recv(4096)
                            if response:
                                logger.info(f"Received from {port}: {response[:100]}...")  # Log first 100 chars
                            else:
                                logger.warning(f"Empty response from {port}")
                                
                    except socket.timeout:
                        logger.warning(f"Timeout on port {port}, reconnecting...")
                        break
                    except Exception as e:
                        logger.error(f"Error on port {port}: {e}")
                        break
                
                logger.info(f"Completed cycle for port {port}, restarting...")
                
        except Exception as e:
            logger.error(f"Connection error on port {port}: {e}, retrying in 5s...")
            time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="Device traffic simulator for TCP/HTTP logs")
    parser.add_argument("log_file", help="Path to log file")
    parser.add_argument("--fast", action="store_true", help="Skip real-time delays")
    args = parser.parse_args()

    # Load port mappings
    base_dir = Path(__file__).parent
    protocol_file = base_dir / 'protocol_ports.json'
    global PORT_PROTOCOL_MAP
    PORT_PROTOCOL_MAP = load_ports(protocol_file)
    logger.info(f"Loaded protocols for ports: {PORT_PROTOCOL_MAP}")

    # Parse and simulate
    messages = parse_log_file(args.log_file)
    if messages:
        try:
            simulate_device_traffic(messages, realtime=not args.fast)
        except KeyboardInterrupt:
            logger.info("Shutdown by user")
    else:
        logger.error("No valid messages found - exiting")

if __name__ == "__main__":
    main()





