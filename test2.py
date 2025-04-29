import socket
import time
import re
import threading
import argparse
import logging
import json
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

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
            except Exception as e:
                logger.warning(f"Timestamp parse failed: {e}")
            return data
    return None

# === CONNECT AND SEND FUNCTION ===
def connect_and_send(hex_data, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            logger.info(f"Connecting to localhost:{port}")
            sock.connect(('127.0.0.1', int(port)))  # Change host as needed
            sock.sendall(bytes.fromhex(hex_data))
            logger.info(f"Sent HEX data to port {port}")
    except Exception as e:
        logger.error(f"Failed to send data to port {port}: {e}")

# === MAIN PROCESSOR ===
def process_log_file(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            data = parse_line(line)
            if data:
                logger.debug(f"Parsed line: {json.dumps(data, cls=DateTimeEncoder)}")
                connect_and_send(data['hex'], data['port'])
                time.sleep(1)  # Simulate delay if needed

# === MAIN ===
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simulate device data from log")
    parser.add_argument('--file', required=True, help='Path to log file')

    args = parser.parse_args()

    logger.info("Starting log processing...")
    process_log_file(args.file)
