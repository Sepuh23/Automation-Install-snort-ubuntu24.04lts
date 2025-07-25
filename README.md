# Automation-Install-snort-ubuntu24.04lts
# Snort IDS Installer Otomatis untuk Ubuntu 24.04

![Snort Logo](https://www.snort.org/assets/images/snort_logo.png)

## 📋 Panduan Lengkap

### 🔧 Prasyarat
- Ubuntu 24.04
- Akses root/sudo
- Interface `enp0s3` aktif
- Minimal 2GB RAM
- 10GB ruang disk

## 📥 File Script Lengkap

### 1. install_snort.sh
```bash
#!/bin/bash
echo "[+] Memulai instalasi Snort..."
sudo apt update -qq && sudo apt upgrade -y -qq
sudo apt install -y -qq snort libpcre3-dev libnet1-dev libdumbnet-dev

echo "[+] Konfigurasi jaringan..."
sudo sed -i "s|ipvar HOME_NET any|ipvar HOME_NET 10.5.50.0/24|g" /etc/snort/snort.conf
sudo sed -i "s|ipvar EXTERNAL_NET any|ipvar EXTERNAL_NET !\$HOME_NET|g" /etc/snort/snort.conf

echo "[+] Setup direktori log..."
sudo mkdir -p /var/log/snort
sudo chown -R snort:snort /var/log/snort

echo "[✓] Instalasi selesai!"
echo "Langkah selanjutnya: sudo ./config_rules.sh"

2. config_rules.sh
bash
#!/bin/bash
echo "[+] Membuat rules custom..."
sudo mkdir -p /etc/snort/rules

cat <<EOF | sudo tee /etc/snort/rules/local.rules
# Rules deteksi ICMP
alert icmp any any -> \$HOME_NET any (msg:"ICMP Flood Terdeteksi"; sid:1000001; rev:1;)

# Rules deteksi port scanning
alert tcp any any -> \$HOME_NET any (msg:"Port Scanning Terdeteksi"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000002; rev:1;)

# Rules deteksi SSH brute force
alert tcp any any -> 10.5.50.5 22 (msg:"SSH Bruteforce Attempt"; content:"Authentication failed"; nocase; sid:1000003; rev:1;)

# Rules deteksi SQL injection
alert tcp any any -> \$HOME_NET 80 (msg:"Possible SQL Injection"; content:"' OR 1=1"; nocase; sid:1000004; rev:1;)
EOF

echo "[+] Validasi konfigurasi..."
sudo snort -T -c /etc/snort/snort.conf -i enp0s3

echo "[✓] Rules berhasil dipasang!"
echo "Langkah selanjutnya: ./monitor_log.sh"

3. monitor_log.sh
bash
#!/bin/bash
clear
echo "[+] Snort IDS Monitoring Tool"
echo "=============================="
echo "Tekan Ctrl+C untuk keluar"
echo ""

while true; do
    echo "=== SERANGAN TERAKHIR ==="
    echo "Waktu: $(date)"
    echo "--------------------------"
    sudo tail -n 5 /var/log/snort/alert 2>/dev/null || echo "Belum ada alert terdeteksi"
    echo ""
    echo "=== STATISTIK ==="
    sudo snort -c /etc/snort/snort.conf -i enp0s3 --dump-stats | grep -E "Received|Dropped|Alerts"
    echo "=============================="
    sleep 5

🚀 Cara Menggunakan
Langkah 1: Install

chmod +x install_snort.sh
sudo ./install_snort.sh

Langkah 2: Konfigurasi

chmod +x config_rules.sh
sudo ./config_rules.sh

Langkah 3: Monitoring

chmod +x monitor_log.sh
./monitor_log.sh

💻 Contoh Output
text
=== SERANGAN TERAKHIR ===
Waktu: Sel Jul 30 14:25:03 WIB 2024
--------------------------
[**] [1:1000001:1] ICMP Flood Terdeteksi [**]
07/30-14:25:01 10.5.50.12 -> 10.5.50.5

=== STATISTIK ===
Received: 1243 packets
Dropped: 0 packets
Alerts: 5 events

 Troubleshooting
Jika interface tidak ditemukan:

sudo ip link set enp0s3 up
Jika Snort gagal start:

sudo snort -T -c /etc/snort/snort.conf -i enp0s3
Untuk update rules:

sudo nano /etc/snort/rules/local.rules
sudo systemctl restart snort

📌 Catatan
Ganti semua 10.5.50.0/24 dengan subnet Anda
Edit enp0s3 jika menggunakan interface berbeda
Sid (Signature ID) harus unik (mulai dari 1000001)
