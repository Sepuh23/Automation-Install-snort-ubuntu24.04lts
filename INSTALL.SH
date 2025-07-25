TAHAP 1: INSTALASI SNORT
bash
#!/bin/bash
# Script 1: install_snort.sh

echo "[+] Memulai instalasi Snort..."
sudo apt update -qq && sudo apt upgrade -y -qq
sudo apt install -y -qq snort libpcre3-dev

echo "[+] Konfigurasi jaringan otomatis..."
sudo sed -i "s|ipvar HOME_NET any|ipvar HOME_NET 10.5.50.0/24|g" /etc/snort/snort.conf
sudo sed -i "s|ipvar EXTERNAL_NET any|ipvar EXTERNAL_NET !10.5.50.0/24|g" /etc/snort/snort.conf

echo "[✓] Snort terinstall! Langkah selanjutnya:"
echo "1. Konfigurasi rules: nano /etc/snort/rules/local.rules"
echo "2. Jalankan Snort: sudo snort -q -i enp0s3 -c /etc/snort/snort.conf -l /var/log/snort"
