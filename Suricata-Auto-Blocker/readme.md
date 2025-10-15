Overview
This project is a simple, Python-based Intrusion Prevention System (IPS). It actively monitors Suricata IDS alerts and dynamically blocks the source IP of detected threats using iptables.

Features
Real-time monitoring of Suricata's alert log.

Dynamic IP blocking and timed unblocking.

Whitelist support to prevent blocking friendly IPs.

Detects ICMP Floods, Port Scans, and SSH Brute-Force attempts.

How It Works
Detect: Suricata identifies a threat based on its ruleset and logs a JSON alert.

Read: The Python script continuously monitors the log file and reads the alert the moment it appears.

Act: The script parses the alert, extracts the source IP, and (after checking a whitelist) issues a command to iptables to block the IP.

Expire: A background process periodically checks the list of blocked IPs and automatically unblocks any whose block time has expired.

Note: This project is a proof-of-concept for lab and educational use. The detection thresholds and block durations are intentionally low for rapid demonstration and would require tuning for a real-world environment.

Project Status
This project is complete and is now archived. It is not actively maintained.
Date of Completion: October 2025
