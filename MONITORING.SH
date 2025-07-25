TAHAP 3: MONITORING LOG
bash
#!/bin/bash
# Script 3: monitor_log.sh

echo "[+] Memantau serangan terkini..."
watch -n 1 'echo "=== SERANGAN TERAKHIR ==="; date; sudo tail -n 5 /var/log/snort/alert; echo ""; echo "=== STATISTIK ==="; sudo snort -c /etc/snort/snort.conf -i enp0s3 --dump-stats'

echo "[✓] Gunakan Ctrl+C untuk berhenti"
echo "Alternatif:"
echo "1. Baca log manual: sudo tail -f /var/log/snort/alert"
echo "2. Analisis paket: sudo snort -r /var/log/snort/snort.log.*"
