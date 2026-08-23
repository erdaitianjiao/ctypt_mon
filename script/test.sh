#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DIR="${PROJECT_DIR}/test"
DISK_SIZE_MB=100
MOUNT_BASE=/mnt/crypt_test

# NixOS: sudo 会重置 PATH，补上系统路径
export PATH="/run/current-system/sw/sbin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/sbin:/nix/var/nix/profiles/default/bin:${PATH}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

check_deps() {
    for cmd in dmsetup losetup mkfs.ext4; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Missing dependency: $cmd"
            exit 1
        fi
    done
}

do_setup() {
    check_deps
    mkdir -p "${TEST_DIR}" "${MOUNT_BASE}"

    # AES: dm-crypt 加密设备
    local name=aes cipher=aes-xts-plain64
    local key="0000000000000000000000000000000000000000000000000000000000000000"
    local img="${TEST_DIR}/${name}.img" mnt="${MOUNT_BASE}/${name}"

    log "Setting up aes (${cipher})..."
    dd if=/dev/zero of="${img}" bs=1M count=${DISK_SIZE_MB} status=none
    local loop
    loop=$(losetup --find --show "${img}")
    log "  Loop: ${loop}"
    local sectors
    sectors=$(blockdev --getsz "${loop}")
    dmsetup create "crypt_test_${name}" --table "0 ${sectors} crypt ${cipher} ${key} 0 ${loop} 0"
    log "  Device: /dev/mapper/crypt_test_${name}"
    mkfs.ext4 -q -F "/dev/mapper/crypt_test_${name}"
    mkdir -p "${mnt}"
    mount "/dev/mapper/crypt_test_${name}" "${mnt}"
    log "  Mounted: ${mnt}"

    # Plain: 不走 dm-crypt，直接 loop 设备
    name=plain
    img="${TEST_DIR}/${name}.img" mnt="${MOUNT_BASE}/${name}"

    log "Setting up plain (direct loop, no dm-crypt)..."
    dd if=/dev/zero of="${img}" bs=1M count=${DISK_SIZE_MB} status=none
    loop=$(losetup --find --show "${img}")
    log "  Loop: ${loop}"
    mkfs.ext4 -q -F "${loop}"
    mkdir -p "${mnt}"
    mount "${loop}" "${mnt}"
    log "  Mounted: ${mnt}"

    log ""
    log "Ready! AES: /mnt/crypt_test/aes | Plain: /mnt/crypt_test/plain"
    log "Run: sudo ./cryptmon"
    log "I/O: sudo bash script/test.sh io"
}

do_teardown() {
    log "Cleaning up..."
    for name in aes plain; do
        umount "${MOUNT_BASE}/${name}" 2>/dev/null || true
        dmsetup remove "crypt_test_${name}" 2>/dev/null || true
    done
    for img in "${TEST_DIR}"/*.img; do
        [ -f "$img" ] || continue
        local loop
        loop=$(losetup -j "${img}" 2>/dev/null | cut -d: -f1)
        [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    done
    rm -f "${TEST_DIR}"/*.img
    rmdir "${MOUNT_BASE}"/{aes,plain} 2>/dev/null || true
    rmdir "${MOUNT_BASE}" 2>/dev/null || true
    log "Cleanup done."
}

do_status() {
    dmsetup ls | grep crypt_test || echo "No dm-crypt devices"
    mount | grep crypt_test || echo "No mounts"
}

do_io() {
    if [ ! -d "${MOUNT_BASE}/aes" ]; then
        err "Test environment not set up. Run: sudo bash script/test.sh setup"
        exit 1
    fi

    if ! command -v fio &>/dev/null; then
        err "fio not found. Install: nix-env -iA nixos.fio"
        exit 1
    fi

    log "Running fio workload..."
    echo ""

    for dev in aes plain; do
        local mnt="${MOUNT_BASE}/${dev}"
        log "--- ${dev} ---"

        # 清理缓存
        sync
        echo 3 > /proc/sys/vm/drop_caches

        # 顺序写
        fio --name=seq_write --directory="${mnt}" --rw=write --bs=4k --size=800k \
            --numjobs=1 2>&1 | grep -E "WRITE:|READ:"
        sync
        echo 3 > /proc/sys/vm/drop_caches
        sleep 1

        # 随机写
        fio --name=rand_write --directory="${mnt}" --rw=randwrite --bs=4k --size=400k \
            --numjobs=1 --fsync=1 2>&1 | grep -E "WRITE:|READ:"
        sync
        echo 3 > /proc/sys/vm/drop_caches
        sleep 2

        # 顺序读
        fio --name=seq_read --directory="${mnt}" --rw=read --bs=4k --size=800k \
            --numjobs=1 2>&1 | grep -E "WRITE:|READ:"
        sync
        echo 3 > /proc/sys/vm/drop_caches
        sleep 1

        # 随机读
        fio --name=rand_read --directory="${mnt}" --rw=randread --bs=4k --size=400k \
            --numjobs=1 2>&1 | grep -E "WRITE:|READ:"
        sync
        echo 3 > /proc/sys/vm/drop_caches
        sleep 2

        log "  done"
        echo ""
    done

    # 清理 fio 生成的文件
    rm -f "${MOUNT_BASE}"/{aes,plain}/seq_write.* "${MOUNT_BASE}"/{aes,plain}/rand_write.* \
          "${MOUNT_BASE}"/{aes,plain}/seq_read.* "${MOUNT_BASE}"/{aes,plain}/rand_read.*

    log "Workload complete."
}

usage() {
    cat <<EOF
Usage: $0 {setup|teardown|status|io}
EOF
}

case "${1:-}" in
    setup)    do_setup ;;
    teardown) do_teardown ;;
    status)   do_status ;;
    io)       do_io ;;
    *)        usage; exit 1 ;;
esac
