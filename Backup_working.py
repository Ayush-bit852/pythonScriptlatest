import socket
import time
import re
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
 
# === DATE ENCODER ===
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)
 
# === LOAD PORT PROTOCOL MAPPING ===
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
 
# === PARSE LOG FILE ===
def parse_log_file(file_path):
    logger.info(f"Reading log file: {file_path}")
    parsed = []
    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            parsed_data = parse_line(line)
            if parsed_data:
                parsed.append(parsed_data)
            else:
                logger.debug(f"Skipping unmatched line {i}")
    return parsed
 
# === SIMULATE TRAFFIC WITH PERSISTENT SOCKET CONNECTIONS ===
def simulate_device_traffic(messages, realtime=True):
    if not messages:
        logger.warning("No messages to simulate.")
        return
 
    messages.sort(key=lambda x: x['timestamp'])
    start_time = messages[0]['timestamp']
    sim_start = time.time()
 
    socket_map = {}
 
    try:
        for msg in messages:
            delay = (msg['timestamp'] - start_time).total_seconds()
            if realtime:
                elapsed = time.time() - sim_start
                sleep_time = delay - elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)
 
            port = int(msg["port"])
            protocol = PORT_PROTOCOL_MAP.get(str(port), "unknown")
            hex_data = msg['hex']
 
            if port not in socket_map:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect(("127.0.0.1", port))
                    socket_map[port] = s
                    logger.info(f"🔗 Connected to 127.0.0.1:{port} ({protocol})")
                except Exception as e:
                    logger.error(f"❌ Connection failed to 127.0.0.1:{port} - {e}")
                    continue
 
            try:
                socket_map[port].sendall(bytes.fromhex(hex_data))
                logger.info(f"📤 Sent to 127.0.0.1:{port} ({protocol}): {hex_data}")
            except Exception as e:
                logger.error(f"❌ Send failed to 127.0.0.1:{port} - {e}")
                socket_map[port].close()
                del socket_map[port]
    finally:
        for s in socket_map.values():
            s.close()
        logger.info("🛑 All sockets closed.")
 
# === MAIN FUNCTION ===
def main():
    parser = argparse.ArgumentParser(description="TCP Simulator for IoT log files (ordered).")
    parser.add_argument("log_file", help="Path to the Traccar log file")
    parser.add_argument("--fast", action="store_true", help="Skip real-time delay (send quickly)")
    args = parser.parse_args()
 
    all_messages = parse_log_file(args.log_file)
    if all_messages:
        simulate_device_traffic(all_messages, realtime=not args.fast)
    else:
        logger.warning("No valid messages found.")
 
if __name__ == "__main__":
    main()