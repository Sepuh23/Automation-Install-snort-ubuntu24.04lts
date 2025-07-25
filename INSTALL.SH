TAHAP 1: INSTALASI SNORT
#!/bin/bash

echo "[+] Memulai instalasi Snort..."

# Update & Upgrade sistem
sudo apt update -qq && sudo apt upgrade -y -qq

# Install Snort dan dependency
sudo apt install -y -qq snort libpcre3 libpcre3-dev build-essential

# Set HOME_NET dan EXTERNAL_NET
echo "[+] Konfigurasi jaringan..."
sudo sed -i 's|ipvar HOME_NET any|ipvar HOME_NET 10.5.50.0/24|' /etc/snort/snort.conf
sudo sed -i 's|ipvar EXTERNAL_NET any|ipvar EXTERNAL_NET !10.5.50.0/24|' /etc/snort/snort.conf

echo "[✓] Instalasi Snort selesai!"
