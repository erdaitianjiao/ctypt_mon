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

require_cmds() {
    local cmd
    for cmd in "$@"; do
        if ! command -v "${cmd}" &>/dev/null; then
            err "Missing dependency: ${cmd}"
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

do_trace() {
    local dev="${2:-aes}"
    local rw="${3:-randread}"
    local runtime="${4:-10}"
    local mnt="${MOUNT_BASE}/${dev}"
    local mapped="/dev/mapper/crypt_test_aes"
    local backing backing_name mapped_name output_dir stamp
    local cryptmon_pid="" dm_trace_pid="" backing_trace_pid=""

    if [ "${dev}" != "aes" ] && [ "${dev}" != "plain" ]; then
        err "Device must be aes or plain"
        exit 1
    fi
    case "${rw}" in
        read|write|randread|randwrite) ;;
        *) err "Workload must be read, write, randread, or randwrite"; exit 1 ;;
    esac
    if ! [[ "${runtime}" =~ ^[1-9][0-9]*$ ]]; then
        err "Runtime must be a positive integer"
        exit 1
    fi
    if [ ! -d "${mnt}" ] || ! mountpoint -q "${mnt}"; then
        err "Test environment not set up. Run: sudo bash script/test.sh setup"
        exit 1
    fi
    if [ "$(id -u)" -ne 0 ]; then
        err "Tracing requires root privileges"
        exit 1
    fi
    require_cmds fio blktrace blkparse lsblk findmnt mountpoint
    if [ ! -x "${PROJECT_DIR}/cryptmon" ]; then
        err "cryptmon not built. Run: nix-shell --run make"
        exit 1
    fi

    if [ "${dev}" = "aes" ]; then
        mapped_name="$(basename "$(readlink -f "${mapped}")")"
        backing_name="$(lsblk -rno KNAME,PKNAME | awk -v name="${mapped_name}" \
            '$1 == name { print $2; exit }')"
        backing="/dev/${backing_name}"
        if [ "${backing}" = "/dev/" ] || [ ! -b "${backing}" ]; then
            err "Cannot resolve backing device for ${mapped}"
            exit 1
        fi
    else
        backing="$(findmnt -n -o SOURCE --target "${mnt}")"
    fi

    stamp="$(date +%Y%m%d-%H%M%S)"
    output_dir="${TEST_DIR}/trace-${dev}-${rw}-${stamp}"
    mkdir -p "${output_dir}"

    cleanup_trace() {
        local pid
        for pid in "${dm_trace_pid}" "${backing_trace_pid}" "${cryptmon_pid}"; do
            if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
                kill -INT "${pid}" 2>/dev/null || true
            fi
        done
        wait 2>/dev/null || true
    }
    trap cleanup_trace EXIT INT TERM

    log "Trace output: ${output_dir}"
    log "Workload: ${dev} ${rw}, ${runtime}s; backing device: ${backing}"

    # 读负载需要在采集开始前创建并写满文件，避免把文件创建和稀疏块读取计入结果。
    if [[ "${rw}" = *read ]]; then
        log "Preparing 64 MiB input file before tracing..."
        fio --name=prepare --filename="${mnt}/trace.dat" --rw=write --bs=1m \
            --size=64m --direct=1 --ioengine=sync --iodepth=1 \
            --numjobs=1 --group_reporting=1 >/dev/null
        sync
    fi

    "${PROJECT_DIR}/cryptmon" >"${output_dir}/cryptmon.log" 2>&1 &
    cryptmon_pid=$!

    if [ "${dev}" = "aes" ]; then
        blktrace -d "${mapped}" -D "${output_dir}" -o dm >"${output_dir}/blktrace-dm.log" 2>&1 &
        dm_trace_pid=$!
    fi
    blktrace -d "${backing}" -D "${output_dir}" -o backing >"${output_dir}/blktrace-backing.log" 2>&1 &
    backing_trace_pid=$!

    sleep 1
    sync
    echo 3 > /proc/sys/vm/drop_caches
    fio --name="cryptmon_${dev}_${rw}" --filename="${mnt}/trace.dat" \
        --rw="${rw}" --bs=4k --size=64m --direct=1 --ioengine=libaio \
        --iodepth=1 --numjobs=1 --time_based=1 --runtime="${runtime}" \
        --group_reporting=1 --output-format=json \
        --output="${output_dir}/fio.json"
    sync

    cleanup_trace
    trap - EXIT INT TERM

    if [ "${dev}" = "aes" ]; then
        blkparse -i "${output_dir}/dm" -d "${output_dir}/dm.bin" \
            -o "${output_dir}/dm.txt"
    fi
    blkparse -i "${output_dir}/backing" -d "${output_dir}/backing.bin" \
        -o "${output_dir}/backing.txt"

    if command -v btt &>/dev/null; then
        if [ "${dev}" = "aes" ]; then
            (cd "${output_dir}" && btt -i dm.bin >dm-btt.txt 2>&1) || true
        fi
        (cd "${output_dir}" && btt -i backing.bin >backing-btt.txt 2>&1) || true
    fi

    rm -f "${mnt}/trace.dat"
    log "Trace complete: ${output_dir}"
    log "Inspect cryptmon.log, fio.json, dm.txt/backing.txt and *-btt.txt"
}

usage() {
    cat <<EOF
Usage: $0 {setup|teardown|status|io|trace [aes|plain] [read|write|randread|randwrite] [seconds]}
EOF
}

case "${1:-}" in
    setup)    do_setup ;;
    teardown) do_teardown ;;
    status)   do_status ;;
    io)       do_io ;;
    trace)    do_trace "$@" ;;
    *)        usage; exit 1 ;;
esac
