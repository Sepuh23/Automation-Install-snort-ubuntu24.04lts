TAHAP 2: KONFIGURASI RULES
#!/bin/bash
# Script 2: config_rules.sh

echo "[+] Membuat rules deteksi dasar..."

cat <<EOF | sudo tee /etc/snort/rules/local.rules
# Deteksi ping flood
alert icmp any any -> 10.5.50.0/24 any (msg:"ICMP Flood"; sid:1001; rev:1;)

# Deteksi port scanning (TCP SYN)
alert tcp any any -> 10.5.50.0/24 any (msg:"Port Scan"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1002; rev:1;)

# Deteksi login SSH gagal
alert tcp any any -> 10.5.50.5 22 (msg:"SSH Bruteforce"; content:"Authentication failed"; sid:1003; rev:1;)

# Deteksi XSS - sederhana (payload mengandung <script>)
alert tcp any any -> 10.5.50.0/24 any (msg:"XSS Detected"; content:"<script>"; nocase; sid:1004; rev:1;)

# Deteksi SQL Injection - sederhana (payload mengandung ' or 1=1 --)
alert tcp any any -> 10.5.50.0/24 any (msg:"SQL Injection Attempt"; content:"' or 1=1 --"; nocase; sid:1005; rev:1;)
EOF

echo "[+] Validasi konfigurasi Snort..."
sudo snort -T -c /etc/snort/snort.conf -i enp0s3

echo "[✓] Rules berhasil dibuat!"
echo "Langkah selanjutnya:"
echo "1. Jalankan Snort: sudo snort -q -i enp0s3 -A fast -l /var/log/snort"
echo "2. Tambah parameter -D untuk jalankan sebagai daemon"
