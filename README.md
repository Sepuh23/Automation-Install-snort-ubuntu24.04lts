# Automation-Install-snort-ubuntu24.04lts
# Snort IDS Installer Otomatis untuk Ubuntu 24.04

CARA MENGGUNAKAN:
Buat 3 file script:

bash
nano install_snort.sh    # Salin isi TAHAP 1
nano config_rules.sh    # Salin isi TAHAP 2
nano monitor_log.sh     # Salin isi TAHAP 3
Berikan hak akses:

bash
chmod +x install_snort.sh config_rules.sh monitor_log.sh
Jalankan berurutan:

bash
sudo ./install_snort.sh
sudo ./config_rules.sh
./monitor_log.sh
HASIL YANG DIHARAPKAN:
Log ICMP Flood saat ada ping ke server:

text
[**] [1:1001:0] ICMP Flood [**]
07/26-14:30:45 10.5.50.10 -> 10.5.50.5
Alert Port Scan saat deteksi scanning:

text
[**] [1:1002:0] Port Scan [**]
07/26-14:32:10 10.5.50.15 -> 10.5.50.5:22
Deteksi Bruteforce SSH:

text
[**] [1:1003:0] SSH Bruteforce [**]
07/26-14:33:22 10.5.50.20 -> 10.5.50.5:22
CATATAN PENTING:
Pastikan interface enp0s3 aktif (ip a show enp0s3)

Untuk jaringan berbeda, ganti semua 10.5.50.0/24 dengan subnet Anda

Rules bisa ditambah/edit di /etc/snort/rules/local.rules
