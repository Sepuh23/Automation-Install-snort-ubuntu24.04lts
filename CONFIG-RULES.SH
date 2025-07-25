TAHAP 2: KONFIGURASI RULES
bash
#!/bin/bash
# Script 2: config_rules.sh

echo "[+] Membuat rules deteksi dasar..."
cat <<EOF | sudo tee /etc/snort/rules/local.rules
# Deteksi ping flood
alert icmp any any -> 10.5.50.0/24 any (msg:"ICMP Flood"; sid:1001;)

# Deteksi port scanning
alert tcp any any -> 10.5.50.0/24 any (msg:"Port Scan"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1002;)

# Deteksi login SSH gagal
alert tcp any any -> 10.5.50.5 22 (msg:"SSH Bruteforce"; content:"Authentication failed"; sid:1003;)
EOF

echo "[+] Validasi konfigurasi..."
sudo snort -T -c /etc/snort/snort.conf -i enp0s3

echo "[✓] Rules berhasil dibuat! Langkah selanjutnya:"
echo "1. Jalankan Snort: sudo snort -q -i enp0s3 -A fast -l /var/log/snort"
echo "2. Untuk mode daemon: tambahkan -D"
