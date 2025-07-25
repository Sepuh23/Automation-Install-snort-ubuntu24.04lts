#!/bin/bash
# rules.sh - Snort Rules for Attack Detection and Defense
# Author: YourName
# Created: $(date)
# Usage: sudo ./rules.sh

echo "[+] Configuring Snort Rules for Attack Detection and Defense..."

# Backup existing rules
sudo cp /etc/snort/rules/local.rules /etc/snort/rules/local.rules.bak 2>/dev/null

# Create new rules file
cat <<EOF | sudo tee /etc/snort/rules/local.rules
# =============================================
# ATTACK DETECTION RULES
# =============================================

# 1. Network Scan/Sweep Detection
alert tcp any any -> \$HOME_NET any (msg:"Network Scan: TCP SYN Scan"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1;)
alert udp any any -> \$HOME_NET any (msg:"Network Scan: UDP Scan"; threshold:type both, track by_src, count 10, seconds 60; sid:1000002; rev:1;)

# 2. DoS/DDoS Detection
alert icmp any any -> \$HOME_NET any (msg:"ICMP Flood Attack"; itype:8; threshold:type both, track by_src, count 50, seconds 10; sid:1000003; rev:1;)
alert tcp any any -> \$HOME_NET any (msg:"SYN Flood Attack"; flags:S; threshold:type both, track by_src, count 100, seconds 10; sid:1000004; rev:1;)

# 3. Brute Force Attacks
alert tcp any any -> \$HOME_NET 22 (msg:"SSH Bruteforce Attempt"; content:"Authentication failed"; threshold:type both, track by_src, count 5, seconds 60; sid:1000005; rev:1;)
alert tcp any any -> \$HOME_NET 21 (msg:"FTP Bruteforce Attempt"; content:"530 Login incorrect"; threshold:type both, track by_src, count 5, seconds 60; sid:1000006; rev:1;)

# 4. Web Application Attacks
alert tcp any any -> \$HOME_NET 80 (msg:"SQL Injection Attempt"; content:"'"; content:"OR"; content:"1=1"; nocase; sid:1000007; rev:1;)
alert tcp any any -> \$HOME_NET 80 (msg:"XSS Attack Attempt"; content:"<script>"; nocase; sid:1000008; rev:1;)
alert tcp any any -> \$HOME_NET 80 (msg:"Directory Traversal Attempt"; content:"../"; nocase; sid:1000009; rev:1;)

# 5. Malware/Exploit Detection
alert tcp any any -> \$HOME_NET any (msg:"Meterpreter Payload Detected"; content:"|00 00 00 00 00 00 00 00|"; sid:1000010; rev:1;)
alert tcp any any -> \$HOME_NET any (msg:"ETERNALBLUE Exploit Attempt"; content:"|FF|SMB|73|"; depth:5; sid:1000011; rev:1;)

# =============================================
# DEFENSE RULES (DROP/REJECT)
# =============================================

# 1. Block Known Malicious IPs
var BAD_IPS [1.1.1.1,2.2.2.2,3.3.3.3]  # Replace with actual bad IPs
drop ip \$BAD_IPS any -> \$HOME_NET any (msg:"Blocked Known Malicious IP"; sid:1000012; rev:1;)

# 2. Block Common Attack Patterns
drop tcp any any -> \$HOME_NET 22 (msg:"Block SSH Bruteforce"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000013; rev:1;)
drop tcp any any -> \$HOME_NET 80 (msg:"Block SQL Injection"; content:"'"; content:"OR"; content:"1=1"; nocase; sid:1000014; rev:1;)

# 3. Block Port Scanning
drop tcp any any -> \$HOME_NET any (msg:"Block Port Scanner"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000015; rev:1;)

# 4. Block ICMP Flood
drop icmp any any -> \$HOME_NET any (msg:"Block ICMP Flood"; itype:8; threshold:type both, track by_src, count 50, seconds 10; sid:1000016; rev:1;)

# 5. Block Known Exploits
drop tcp any any -> \$HOME_NET any (msg:"Block ETERNALBLUE Exploit"; content:"|FF|SMB|73|"; depth:5; sid:1000017; rev:1;)
EOF

# Validate configuration
echo "[+] Validating rules..."
sudo snort -T -c /etc/snort/snort.conf -i enp0s3

# Restart Snort
echo "[+] Restarting Snort..."
sudo systemctl restart snort

echo "[✓] Rules successfully configured!"
echo "Custom rules file: /etc/snort/rules/local.rules"
echo "To monitor alerts: sudo tail -f /var/log/snort/alert"
