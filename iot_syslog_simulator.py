#!/usr/bin/env python3
"""
IoT Device Syslog Simulator
Simulates an IoT device generating syslog messages with various events
"""

import time
import random
import socket
import json
from datetime import datetime

class IoTSyslogSimulator:
    def __init__(self, device_name="IoT-Device-001", device_ip="192.168.1.100"):
        self.device_name = device_name
        self.device_ip = device_ip
        self.facility = 16  # local0
        
        # Syslog severity levels
        self.EMERGENCY = 0
        self.ALERT = 1
        self.CRITICAL = 2
        self.ERROR = 3
        self.WARNING = 4
        self.NOTICE = 5
        self.INFO = 6
        self.DEBUG = 7
        
        # IoT device event types
        self.event_types = [
            {"type": "temperature_reading", "severity": self.INFO, "weight": 40},
            {"type": "humidity_reading", "severity": self.INFO, "weight": 30},
            {"type": "motion_detected", "severity": self.NOTICE, "weight": 10},
            {"type": "low_battery", "severity": self.WARNING, "weight": 5},
            {"type": "connection_lost", "severity": self.ERROR, "weight": 3},
            {"type": "sensor_malfunction", "severity": self.CRITICAL, "weight": 2},
            {"type": "firmware_update", "severity": self.NOTICE, "weight": 5},
            {"type": "device_reboot", "severity": self.WARNING, "weight": 3},
            {"type": "authentication_success", "severity": self.INFO, "weight": 1},
            {"type": "authentication_failed", "severity": self.WARNING, "weight": 1},
        ]
    
    def calculate_priority(self, facility, severity):
        """Calculate syslog priority value"""
        return (facility * 8) + severity
    
    def generate_event_data(self, event_type):
        """Generate realistic data based on event type"""
        if event_type == "temperature_reading":
            return {"temperature": round(random.uniform(18.0, 30.0), 2), "unit": "C"}
        elif event_type == "humidity_reading":
            return {"humidity": round(random.uniform(30.0, 70.0), 2), "unit": "%"}
        elif event_type == "motion_detected":
            return {"location": random.choice(["front_door", "living_room", "backyard", "garage"])}
        elif event_type == "low_battery":
            return {"battery_level": random.randint(5, 20), "unit": "%"}
        elif event_type == "connection_lost":
            return {"network": "WiFi", "retry_count": random.randint(1, 5)}
        elif event_type == "sensor_malfunction":
            return {"sensor": random.choice(["temp_sensor", "humidity_sensor", "motion_sensor"])}
        elif event_type == "firmware_update":
            return {"version": f"v{random.randint(1,3)}.{random.randint(0,9)}.{random.randint(0,20)}"}
        elif event_type == "device_reboot":
            return {"reason": random.choice(["scheduled", "watchdog", "manual"])}
        elif event_type == "authentication_success":
            return {"user": "admin", "method": "token"}
        elif event_type == "authentication_failed":
            return {"user": random.choice(["admin", "unknown"]), "reason": "invalid_credentials"}
        return {}
    
    def format_syslog_message(self, severity, event_type, data):
        """Format message in standard syslog format (RFC 3164)"""
        priority = self.calculate_priority(self.facility, severity)
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        
        # Create structured message
        message = f"{event_type.upper()}: {json.dumps(data)}"
        
        # RFC 3164 format: <priority>timestamp hostname tag: message
        syslog_msg = f"<{priority}>{timestamp} {self.device_name} IoTDevice[{random.randint(1000,9999)}]: {message}"
        
        return syslog_msg
    
    def select_random_event(self):
        """Select a random event based on weights"""
        events = [e["type"] for e in self.event_types]
        weights = [e["weight"] for e in self.event_types]
        return random.choices(events, weights=weights)[0]
    
    def get_event_severity(self, event_type):
        """Get severity level for an event type"""
        for event in self.event_types:
            if event["type"] == event_type:
                return event["severity"]
        return self.INFO
    
    def generate_log(self):
        """Generate a single syslog message"""
        event_type = self.select_random_event()
        severity = self.get_event_severity(event_type)
        data = self.generate_event_data(event_type)
        
        syslog_msg = self.format_syslog_message(severity, event_type, data)
        return syslog_msg
    
    def send_to_syslog_server(self, syslog_msg, server_host="127.0.0.1", server_port=514):
        """Send syslog message to a syslog server via UDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(syslog_msg.encode('utf-8'), (server_host, server_port))
            sock.close()
            return True
        except Exception as e:
            print(f"Error sending to syslog server: {e}")
            return False
    
    def run(self, mode="console", interval=2, count=None, server_host="127.0.0.1", server_port=514):
        """
        Run the simulator
        
        Args:
            mode: "console" to print logs, "network" to send to syslog server, "both" for both
            interval: seconds between log generation
            count: number of logs to generate (None for infinite)
            server_host: syslog server hostname/IP
            server_port: syslog server port
        """
        print(f"IoT Syslog Simulator Started")
        print(f"Device: {self.device_name} ({self.device_ip})")
        print(f"Mode: {mode}")
        if mode in ["network", "both"]:
            print(f"Target Server: {server_host}:{server_port}")
        print(f"Interval: {interval}s")
        print("-" * 80)
        
        log_count = 0
        try:
            while count is None or log_count < count:
                syslog_msg = self.generate_log()
                
                if mode in ["console", "both"]:
                    print(f"[{log_count + 1}] {syslog_msg}")
                
                if mode in ["network", "both"]:
                    success = self.send_to_syslog_server(syslog_msg, server_host, server_port)
                    if mode == "network" and success:
                        print(f"[{log_count + 1}] Sent to {server_host}:{server_port}")
                
                log_count += 1
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print(f"\n\nSimulator stopped. Generated {log_count} logs.")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="IoT Device Syslog Simulator")
    parser.add_argument("--device-name", default="IoT-Device-001", help="Device name")
    parser.add_argument("--device-ip", default="192.168.1.100", help="Device IP address")
    parser.add_argument("--mode", choices=["console", "network", "both"], default="console",
                        help="Output mode: console (print), network (send to server), or both")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between logs")
    parser.add_argument("--count", type=int, default=None, help="Number of logs to generate (default: infinite)")
    parser.add_argument("--server", default="127.0.0.1", help="Syslog server host")
    parser.add_argument("--port", type=int, default=514, help="Syslog server port")
    
    args = parser.parse_args()
    
    simulator = IoTSyslogSimulator(
        device_name=args.device_name,
        device_ip=args.device_ip
    )
    
    simulator.run(
        mode=args.mode,
        interval=args.interval,
        count=args.count,
        server_host=args.server,
        server_port=args.port
    )
