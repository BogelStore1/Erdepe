#!/usr/bin/env bash
set -euo pipefail

#############################################
# Windows DD + FirstBoot Injector (DO KVM)
# - Auto-detect IP/GW/DNS on Linux
# - wget .gz image, dd to disk
# - mount NTFS windows partition
# - inject SetupComplete.bat + firstboot.ps1 + AutoExtendAllDisk.bat
#############################################

### ===== USER SETTINGS (EDIT) =====
IMAGE_URL="https://image.yha.my.id/2:/windows10.gz"

TARGET_DISK="/dev/vda"      # DO biasanya /dev/vda
RDP_PORT="9980"
ADMIN_PASSWORD="Bogelganteng123!"

# network: "dhcp" (disarankan DO) atau "static"
NET_MODE="dhcp"

# Safety switch: harus YES biar jalan
FORCE="${FORCE:-NO}"
### =================================

log(){ echo -e "[$(date -Is)] $*"; }
die(){ echo -e "ERROR: $*" >&2; exit 1; }

need_root(){ [[ "${EUID}" -eq 0 ]] || die "Jalankan sebagai root."; }

install_deps(){
  log "Install dependency..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wget pv gzip qemu-utils ntfs-3g util-linux dos2unix
}

preflight(){
  need_root
  [[ "$FORCE" == "YES" ]] || die "Safety stop. Jalankan dengan: FORCE=YES bash $0"

  [[ -b "$TARGET_DISK" ]] || die "TARGET_DISK tidak ada: $TARGET_DISK"

  if [[ "${#ADMIN_PASSWORD}" -lt 12 ]]; then
    die "ADMIN_PASSWORD minimal 12 karakter."
  fi

  if ! [[ "$RDP_PORT" =~ ^[0-9]+$ ]] || (( RDP_PORT < 1 || RDP_PORT > 65535 )); then
    die "RDP_PORT invalid: $RDP_PORT"
  fi

  if [[ "$NET_MODE" != "dhcp" && "$NET_MODE" != "static" ]]; then
    die "NET_MODE harus 'dhcp' atau 'static'"
  fi

  log "TARGET_DISK = $TARGET_DISK (AKAN DI-OVERWRITE!)"
  lsblk "$TARGET_DISK" || true
}

detect_network(){
  log "Auto-detect network (Linux)..."

  # Default interface (via default route)
  local def_if
  def_if="$(ip -o -4 route show to default | awk '{print $5}' | head -n1 || true)"
  [[ -n "${def_if:-}" ]] || die "Gagal detect default interface (ip route default)."

  # IP/prefix
  local ip_cidr
  ip_cidr="$(ip -o -4 addr show dev "$def_if" | awk '{print $4}' | head -n1 || true)"
  [[ -n "${ip_cidr:-}" ]] || die "Gagal detect IPv4 di interface $def_if."

  local ipaddr prefix
  ipaddr="${ip_cidr%/*}"
  prefix="${ip_cidr#*/}"

  # Gateway
  local gateway
  gateway="$(ip -o -4 route show to default | awk '{print $3}' | head -n1 || true)"
  [[ -n "${gateway:-}" ]] || gateway=""

  # DNS dari resolv.conf (ambil 2 pertama)
  local dns1 dns2
  dns1="$(awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf | head -n1 || true)"
  dns2="$(awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf | sed -n '2p' || true)"

  # fallback kalau kosong
  [[ -n "${dns1:-}" ]] || dns1="1.1.1.1"
  [[ -n "${dns2:-}" ]] || dns2="8.8.8.8"

  export DET_IF="$def_if" DET_IP="$ipaddr" DET_PREFIX="$prefix" DET_GW="$gateway" DET_DNS1="$dns1" DET_DNS2="$dns2"

  log "Detected: IF=$DET_IF IP=$DET_IP/$DET_PREFIX GW=$DET_GW DNS=$DET_DNS1,$DET_DNS2"
}

download_image(){
  mkdir -p /tmp/win-dd
  cd /tmp/win-dd
  log "Download image: $IMAGE_URL"
  wget -O windows.gz "$IMAGE_URL"
  log "Downloaded: $(ls -lh windows.gz | awk '{print $5}')"
}

dd_image(){
  cd /tmp/win-dd
  log "Mulai dd ke $TARGET_DISK (INI MENGHAPUS DISK!)"
  sync
  pv windows.gz | gunzip -c | dd of="$TARGET_DISK" bs=16M status=progress conv=fsync
  sync
  log "DD selesai."
}

refresh_partitions(){
  log "Refresh partition table..."
  partprobe "$TARGET_DISK" || true
  udevadm settle || true
  sleep 2
  lsblk -f "$TARGET_DISK" || true
}

find_windows_ntfs_partition(){
  # Pilih partisi NTFS terbesar (paling sering adalah C:)
  local part
  part="$(lsblk -lnpo NAME,FSTYPE,SIZE "$TARGET_DISK" \
    | awk '$2=="ntfs"{print $1" "$3}' \
    | sort -hrk2 \
    | head -n1 \
    | awk '{print $1}')"

  [[ -n "${part:-}" ]] || die "Tidak menemukan partisi NTFS pada $TARGET_DISK setelah dd."
  echo "$part"
}

inject_scripts(){
  local winpart="$1"
  local mnt="/mnt/win"
  local scripts_dir

  log "Mount Windows partition: $winpart -> $mnt"
  mkdir -p "$mnt"
  mount -t ntfs-3g -o rw,uid=0,gid=0 "$winpart" "$mnt"

  scripts_dir="$mnt/Windows/Setup/Scripts"
  mkdir -p "$scripts_dir"

  # SetupComplete.bat (bukan .cmd)
  cat > "$scripts_dir/SetupComplete.bat" <<'BAT'
@echo off
REM === SetupComplete.bat runs at end of Windows setup (if image is generalized/sysprepped) ===

REM Run first-boot PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File "%WINDIR%\Setup\Scripts\firstboot.ps1"

REM Auto-extend disk/partition
call "%WINDIR%\Setup\Scripts\AutoExtendAllDisk.bat"

exit /b 0
BAT

  # AutoExtendAllDisk.bat
  # Extend C: to maximum supported size
  cat > "$scripts_dir/AutoExtendAllDisk.bat" <<'BAT'
@echo off
setlocal

REM Extend system partition (C:) to maximum size
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='SilentlyContinue';" ^
  "$dl='C';" ^
  "$p=Get-Partition -DriveLetter $dl;" ^
  "if($p){$s=Get-PartitionSupportedSize -DriveLetter $dl; Resize-Partition -DriveLetter $dl -Size $s.SizeMax;}" ^
  "exit 0"

endlocal
exit /b 0
BAT

  # firstboot.ps1: set password, RDP, port, firewall, network
  # Pakai NET_MODE (dhcp/static). Kalau static, pakai hasil detect dari Linux (DET_*)
  cat > "$scripts_dir/firstboot.ps1" <<PS1
\$ErrorActionPreference = "Stop"

# === Injected config ===
\$AdminPassword = "${ADMIN_PASSWORD}"
\$RdpPort = ${RDP_PORT}

\$NetMode = "${NET_MODE}"     # dhcp / static
\$IpAddr = "${DET_IP}"
\$PrefixLen = ${DET_PREFIX}
\$Gateway = "${DET_GW}"
\$Dns1 = "${DET_DNS1}"
\$Dns2 = "${DET_DNS2}"

Write-Host "== Firstboot start =="

# Set Administrator password
try {
  net user Administrator "\$AdminPassword" | Out-Null
  Write-Host "Administrator password set."
} catch {
  Write-Host "Failed setting password: \$($_.Exception.Message)"
}

# Enable RDP
try {
  reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null
  Write-Host "RDP enabled."
} catch {
  Write-Host "Failed enabling RDP: \$($_.Exception.Message)"
}

# Set RDP port
try {
  reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v PortNumber /t REG_DWORD /d \$RdpPort /f | Out-Null
  Write-Host "RDP port set to \$RdpPort."
} catch {
  Write-Host "Failed setting RDP port: \$($_.Exception.Message)"
}

# Firewall allow RDP custom port
try {
  netsh advfirewall firewall add rule name="RDP Custom Port" dir=in action=allow protocol=TCP localport=\$RdpPort | Out-Null
  Write-Host "Firewall rule added for TCP \$RdpPort."
} catch {
  Write-Host "Failed adding firewall rule: \$($_.Exception.Message)"
}

# Network configuration
try {
  \$adapter = Get-NetAdapter | Where-Object { \$_.Status -eq "Up" } | Select-Object -First 1
  if (-not \$adapter) { throw "No active network adapter found." }

  if (\$NetMode -eq "dhcp") {
    Write-Host "Setting DHCP on adapter: \$((\$adapter).Name)"
    Set-NetIPInterface -InterfaceIndex \$adapter.ifIndex -Dhcp Enabled | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex \$adapter.ifIndex -ResetServerAddresses | Out-Null
  } else {
    Write-Host "Setting STATIC IP on adapter: \$((\$adapter).Name) => \$IpAddr/\$PrefixLen gw \$Gateway"
    Get-NetIPAddress -InterfaceIndex \$adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:\$false -ErrorAction SilentlyContinue
    if (\$Gateway -and \$Gateway.Length -gt 0) {
      New-NetIPAddress -InterfaceIndex \$adapter.ifIndex -IPAddress \$IpAddr -PrefixLength \$PrefixLen -DefaultGateway \$Gateway | Out-Null
    } else {
      New-NetIPAddress -InterfaceIndex \$adapter.ifIndex -IPAddress \$IpAddr -PrefixLength \$PrefixLen | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex \$adapter.ifIndex -ServerAddresses @(\$Dns1,\$Dns2) | Out-Null
  }
  Write-Host "Network configured (\$NetMode)."
} catch {
  Write-Host "Network config failed: \$($_.Exception.Message)"
}

Write-Host "== Firstboot done. Rebooting in 10 seconds =="
Start-Sleep -Seconds 10
Restart-Computer -Force
PS1

  # Convert to DOS line endings for bat (lebih aman)
  if command -v unix2dos >/dev/null 2>&1; then
    unix2dos -q "$scripts_dir/SetupComplete.bat" "$scripts_dir/AutoExtendAllDisk.bat" || true
  fi

  sync
  umount "$mnt"
  log "Inject selesai: SetupComplete.bat + firstboot.ps1 + AutoExtendAllDisk.bat"
}

main(){
  preflight
  install_deps
  detect_network
  download_image
  dd_image
  refresh_partitions
  local winpart
  winpart="$(find_windows_ntfs_partition)"
  inject_scripts "$winpart"

  log "SELESAI."
  log "Next: Power Off/On droplet dari panel DO (atau reboot)."
  log "RDP: IP droplet, port ${RDP_PORT}"
  log "Net mode: ${NET_MODE} (detected IP/GW/DNS injected for static mode)."
}

main "$@"
