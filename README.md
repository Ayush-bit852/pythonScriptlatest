
# TCP Simulator for Traccar HEX Logs

This script reads a Traccar-style log file and simulates TCP messages sent from IoT devices to specific ports.

## Requirements

- Python 3.8+
- No external dependencies

## How to Run

```bash
python simulate_device.py /path/to/tracker-server.log
```

To simulate fast (no real-time delay):

```bash
python simulate_device.py /path/to/tracker-server.log --fast
```

## How it Works

- Parses each line for timestamp, session ID, IP, port, and HEX data.
- Sends HEX payloads over TCP to the appropriate local port.
- Supports multiple ports and real-time simulation.
