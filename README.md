# Automation-Install-snort-ubuntu24.04lts
# Snort IDS Installer Otomatis untuk Ubuntu 24.04

![Snort Logo](https://www.snort.org/assets/images/snort_logo.png)

## 📋 Panduan 3 Langkah Lengkap

### 1. INSTALASI SNORT
**File:** `install_snort.sh`

**Langkah-langkah:**
1. Buka terminal
2. Clone repository:
   ```bash
   git clone https://github.com/username/snort-ubuntu-autoinstall.git
   cd snort-ubuntu-autoinstall
Berikan hak akses:

bash
chmod +x install_snort.sh
Jalankan instalasi:

bash
sudo ./install_snort.sh
Yang dilakukan script:

Mengupdate paket Ubuntu

Menginstall Snort dan semua dependensi

Mengatur jaringan lokal ke 10.5.50.0/24

Membuat folder log di /var/log/snort

2. KONFIGURASI RULES
File: config_rules.sh

Langkah-langkah:

Pastikan sudah berada di folder project

Berikan hak akses:

bash
chmod +x config_rules.sh
Jalankan konfigurasi:

bash
sudo ./config_rules.sh
Rules yang ditambahkan:

🚨 Deteksi ICMP Flood (serangan ping)

🔍 Alarm Port Scanning

🔒 Peringatan Bruteforce SSH

⚠️ Deteksi traffic mencurigakan

3. MONITORING LOG
File: monitor_log.sh

Langkah-langkah:

Pastikan sudah berada di folder project

Berikan hak akses:

bash
chmod +x monitor_log.sh
Jalankan monitoring:

bash
./monitor_log.sh
Fitur monitoring:

🔄 Update real-time setiap 1 detik

📜 Menampilkan 5 alert terbaru

📊 Statistik traffic jaringan

⏹️ Tekan Ctrl+C untuk berhenti

🖥️ Contoh Output
text
[=== ALERT TERAKHIR ===]
[**] [1:1001:0] ICMP Flood Terdeteksi [**]
07/28-14:25:03 10.5.50.15 -> 10.5.50.5

[=== STATISTIK TRAFIK ===]
Total paket dianalisis: 1,243
Alert yang terdeteksi: 12
⁉️ Troubleshooting
Jika ada masalah:

bash
# Cek status Snort
sudo systemctl status snort

# Tes konfigurasi
sudo snort -T -c /etc/snort/snort.conf -i enp0s3

# Lihat error log
tail -f /var/log/syslog | grep snort
