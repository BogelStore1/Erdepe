#!/usr/bin/env bash
set -euo pipefail

echo "Windows Installer (Revised) - Port RDP 9980"
echo

# ====== Konfigurasi ======
RDP_PORT="9980"

# ====== Cek root ======
if [[ $EUID -ne 0 ]]; then
  echo "[!] Jalankan sebagai root."
  exit 1
fi

# ====== Cek dependency ======
need_cmds=(curl wget gunzip dd ip awk findmnt lsblk mount.ntfs-3g)
missing=()
for c in "${need_cmds[@]}"; do
  command -v "$c" >/dev/null 2>&1 || missing+=("$c")
done
if ((${#missing[@]})); then
  echo "[!] Command berikut belum ada: ${missing[*]}"
  echo "    Install dulu (contoh Debian/Ubuntu): apt-get update && apt-get install -y curl wget gzip coreutils iproute2 gawk util-linux ntfs-3g"
  echo "    Atau sesuaikan dengan distro kamu (yum/dnf/apk)."
  exit 1
fi

# ====== Menu OS ======
echo "Pilih OS yang ingin anda install"
echo "[1] Windows 2019 (Default)"
echo "[2] Windows 2016"
echo "[3] Windows 2012"
echo "[4] Windows 10"
echo "[5] Custom Link Zip (GZ)"
echo

read -r -p "Pilih [1]: " PILIHOS
PILIHOS="${PILIHOS:-1}"

case "$PILIHOS" in
  1) OS_URL="https://nixpoin.sgp1.cdn.digitaloceanspaces.com/windows2019DO.gz" ;;
  2) OS_URL="https://nixpoin.sgp1.cdn.digitaloceanspaces.com/windows2016.gz" ;;
  3) OS_URL="https://nixpoin.sgp1.cdn.digitaloceanspaces.com/windows2012v2.gz" ;;
  4) OS_URL="https://image.yha.my.id/2:/windows10.gz" ;;
  5) read -r -p "[?] Link ZIP (GZ): " OS_URL ;;
  *) echo "[!] Pilihan salah"; exit 1 ;;
esac

# ====== Password admin ======
while true; do
  read -r -s -p "[?] Password Administrator (Minimal 12 Karakter): " PASSADMIN
  echo
  if ((${#PASSADMIN} < 12)); then
    echo "[!] Password minimal 12 karakter. Coba lagi."
    continue
  fi
  read -r -s -p "[?] Ulangi Password: " PASS2
  echo
  if [[ "$PASSADMIN" != "$PASS2" ]]; then
    echo "[!] Password tidak sama. Coba lagi."
    continue
  fi
  break
done

# ====== Detect interface utama + IP/GW/NETMASK ======
DEF_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
if [[ -z "${DEF_IF:-}" ]]; then
  echo "[!] Gagal mendeteksi interface default."
  exit 1
fi

CIDR=$(ip -4 addr show dev "$DEF_IF" | awk '/inet /{print $2; exit}')
if [[ -z "${CIDR:-}" ]]; then
  echo "[!] Gagal mengambil IPv4 dari interface $DEF_IF"
  exit 1
fi

IP4="${CIDR%/*}"
PREFIX="${CIDR#*/}"
GW=$(ip route | awk '/default/ {print $3; exit}')

# Convert prefix (CIDR) -> netmask dotted
cidr2mask() {
  local p=$1
  local mask=""
  local full=$((p/8))
  local rem=$((p%8))
  local i
  for ((i=0;i<4;i++)); do
    local oct=0
    if (( i < full )); then
      oct=255
    elif (( i == full )); then
      oct=$(( 256 - 2**(8-rem) ))
      if (( rem == 0 )); then oct=0; fi
    else
      oct=0
    fi
    mask+="$oct"
    [[ $i -lt 3 ]] && mask+="."
  done
  echo "$mask"
}

NETMASK="$(cidr2mask "$PREFIX")"

# ====== Detect disk utama (tempat / berada) ======
ROOT_SRC=$(findmnt -n -o SOURCE /)          # contoh: /dev/vda1 atau /dev/nvme0n1p1
DISK="/dev/$(lsblk -no PKNAME "$ROOT_SRC")" # contoh: /dev/vda atau /dev/nvme0n1

if [[ -z "${DISK:-}" || ! -b "$DISK" ]]; then
  echo "[!] Gagal mendeteksi disk utama dari root: $ROOT_SRC"
  exit 1
fi

echo "=== Ringkasan ==="
echo "OS URL   : $OS_URL"
echo "Disk     : $DISK  (AKAN DIHAPUS TOTAL!)"
echo "IFACE    : $DEF_IF"
echo "IP       : $IP4/$PREFIX"
echo "NETMASK  : $NETMASK"
echo "GATEWAY  : $GW"
echo "RDP PORT : $RDP_PORT"
echo

read -r -p "Ketik 'YES' untuk lanjut (ini menghapus semua data di $DISK): " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
  echo "[!] Dibatalkan."
  exit 0
fi

# ====== Buat net.bat (Windows Startup) ======
cat >/tmp/net.bat <<EOF
@ECHO OFF
cd.>%windir%\\GetAdmin
if exist %windir%\\GetAdmin (del /f /q "%windir%\\GetAdmin") else (
echo CreateObject^("Shell.Application"^).ShellExecute "%~s0", "%*", "", "runas", 1 >> "%temp%\\Admin.vbs"
"%temp%\\Admin.vbs"
del /f /q "%temp%\\Admin.vbs"
exit /b 2)

net user Administrator "$PASSADMIN"

for /f "tokens=1,*" %%A in ('netsh interface show interface ^| findstr /I /R "Connected.*Ethernet"') do (set InterfaceName=%%B)

if "%InterfaceName%"=="" (
  rem fallback common name:
  set InterfaceName=Ethernet
)

netsh -c interface ip set address name="%InterfaceName%" source=static address=$IP4 mask=$NETMASK gateway=$GW
netsh -c interface ip add dnsservers name="%InterfaceName%" address=8.8.8.8 index=1 validate=no
netsh -c interface ip add dnsservers name="%InterfaceName%" address=8.8.4.4 index=2 validate=no

cd /d "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
del /f /q net.bat
exit
EOF

# ====== Buat dpart.bat (Windows Startup) ======
cat >/tmp/dpart.bat <<EOF
@ECHO OFF
echo CREATING RDP WITH PORT $IP4:$RDP_PORT
echo NOTE : TYPE YES AND ENTER (if prompted)

cd.>%windir%\\GetAdmin
if exist %windir%\\GetAdmin (del /f /q "%windir%\\GetAdmin") else (
echo CreateObject^("Shell.Application"^).ShellExecute "%~s0", "%*", "", "runas", 1 >> "%temp%\\Admin.vbs"
"%temp%\\Admin.vbs"
del /f /q "%temp%\\Admin.vbs"
exit /b 2)

set PORT=$RDP_PORT
set RULE_NAME=Open Port %PORT%

netsh advfirewall firewall show rule name="%RULE_NAME%" >nul 2>&1
if not ERRORLEVEL 1 (
  echo Rule "%RULE_NAME%" already exists.
) else (
  echo Creating firewall rule "%RULE_NAME%" ...
  netsh advfirewall firewall add rule name="%RULE_NAME%" dir=in action=allow protocol=TCP localport=%PORT%
)

rem Set RDP port in registry (Decimal):
reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v PortNumber /t REG_DWORD /d $RDP_PORT /f

rem Extend system volume to max
ECHO SELECT VOLUME=%%SystemDrive%% > "%SystemDrive%\\diskpart.extend"
ECHO EXTEND >> "%SystemDrive%\\diskpart.extend"
START /WAIT DISKPART /S "%SystemDrive%\\diskpart.extend"
del /f /q "%SystemDrive%\\diskpart.extend"

cd /d "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
del /f /q dpart.bat

timeout 30 >nul
del /f /q ChromeSetup.exe
echo JENDELA INI JANGAN DITUTUP
exit
EOF

# ====== Tulis image Windows ke disk ======
echo "[*] Download + write image ke $DISK ..."
wget --no-check-certificate -O- "$OS_URL" | gunzip | dd of="$DISK" bs=4M status=progress conv=fsync

# ====== Mount partisi Windows (umumnya partisi 2) ======
WIN_PART="${DISK}2"
if [[ ! -b "$WIN_PART" ]]; then
  # fallback untuk nvme naming (p2)
  if [[ -b "${DISK}p2" ]]; then
    WIN_PART="${DISK}p2"
  else
    echo "[!] Partisi Windows tidak ditemukan (${DISK}2 / ${DISK}p2)."
    echo "    Cek manual dengan: lsblk"
    exit 1
  fi
fi

mkdir -p /mnt
mount.ntfs-3g "$WIN_PART" /mnt

# ====== Copy startup scripts + download Chrome ======
STARTUP_DIR="/mnt/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"
if [[ ! -d "$STARTUP_DIR" ]]; then
  echo "[!] Folder Startup tidak ditemukan: $STARTUP_DIR"
  echo "    Struktur image mungkin berbeda."
  exit 1
fi

echo "[*] Download ChromeSetup.exe ke Programs folder..."
PROG_DIR="/mnt/ProgramData/Microsoft/Windows/Start Menu/Programs"
wget -q -O "$PROG_DIR/ChromeSetup.exe" "https://nixpoin.com/ChromeSetup.exe" || true

echo "[*] Menyalin net.bat & dpart.bat ke Startup..."
cp -f /tmp/net.bat "$STARTUP_DIR/net.bat"
cp -f /tmp/dpart.bat "$STARTUP_DIR/dpart.bat"

sync
umount /mnt || true

echo
echo "[✓] Selesai. REBOOT VPS SEKARANG."
echo "    Setelah boot Windows, RDP gunakan:"
echo "    IP   : $IP4"
echo "    Port : $RDP_PORT"
echo "    User : Administrator"
