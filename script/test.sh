#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DIR="${PROJECT_DIR}/test"
DISK_SIZE_MB="${CRYPTMON_DISK_SIZE_MB:-256}"
MOUNT_BASE="${CRYPTMON_MOUNT_BASE:-/mnt/crypt_test}"
BENCH_SIZE="${CRYPTMON_BENCH_SIZE:-64m}"

# NixOS: sudo 会重置 PATH，补上系统路径
export PATH="/run/current-system/sw/sbin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/sbin:/nix/var/nix/profiles/default/bin:${PATH}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This command requires root privileges"
        exit 1
    fi
}

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
    require_root
    check_deps
    require_cmds blockdev mount mountpoint

    if dmsetup info crypt_test_aes &>/dev/null ||
       mountpoint -q "${MOUNT_BASE}/aes" || mountpoint -q "${MOUNT_BASE}/plain" ||
       [ -e "${TEST_DIR}/aes.img" ] || [ -e "${TEST_DIR}/plain.img" ]; then
        err "Existing crypt_mon test environment detected; refusing to overwrite it"
        err "Inspect with: $0 status; remove explicitly with: $0 teardown"
        exit 1
    fi
    mkdir -p "${TEST_DIR}" "${MOUNT_BASE}"
    trap 'err "Setup failed; removing the partially created environment"; do_teardown' ERR

    # AES: dm-crypt 加密设备
    local name=aes cipher=aes-xts-plain64
    local key="0000000000000000000000000000000000000000000000000000000000000000"
    local img="${TEST_DIR}/${name}.img" mnt="${MOUNT_BASE}/${name}"

    log "Setting up aes (${cipher})..."
    dd if=/dev/zero of="${img}" bs=1M count="${DISK_SIZE_MB}" status=none
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
    dd if=/dev/zero of="${img}" bs=1M count="${DISK_SIZE_MB}" status=none
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
    trap - ERR
}

do_teardown() {
    require_root
    log "Cleaning up..."
    for name in aes plain; do
        umount "${MOUNT_BASE}/${name}" 2>/dev/null || true
        dmsetup remove "crypt_test_${name}" 2>/dev/null || true
    done
    for img in "${TEST_DIR}/aes.img" "${TEST_DIR}/plain.img"; do
        [ -f "$img" ] || continue
        local loop
        loop=$(losetup -j "${img}" 2>/dev/null | cut -d: -f1)
        [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    done
    rm -f "${TEST_DIR}/aes.img" "${TEST_DIR}/plain.img"
    rmdir "${MOUNT_BASE}"/{aes,plain} 2>/dev/null || true
    rmdir "${MOUNT_BASE}" 2>/dev/null || true
    log "Cleanup done."
}

do_status() {
    require_root
    dmsetup ls 2>/dev/null | grep crypt_test || echo "No dm-crypt devices"
    findmnt -rn | grep "${MOUNT_BASE}" || echo "No crypt_mon mounts"
}

do_io() {
    require_root
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

prepare_benchmark_file() {
    local dev="$1"
    local file="${MOUNT_BASE}/${dev}/bench.dat"

    if [ ! -f "${file}" ]; then
        log "Preparing ${BENCH_SIZE} benchmark file on ${dev}..."
        fio --name="prepare_${dev}" --filename="${file}" --rw=write --bs=1m \
            --size="${BENCH_SIZE}" --direct=1 --ioengine=sync --iodepth=1 \
            --numjobs=1 --group_reporting=1 >/dev/null
        sync
    fi
}

do_benchmark() {
    local runtime="${2:-5}"
    local rounds="${3:-3}"
    local stamp output_dir round dev rw

    require_root
    require_cmds fio jq mountpoint
    if ! [[ "${runtime}" =~ ^[1-9][0-9]*$ ]] ||
       ! [[ "${rounds}" =~ ^[1-9][0-9]*$ ]]; then
        err "Runtime and rounds must be positive integers"
        exit 1
    fi
    for dev in aes plain; do
        if ! mountpoint -q "${MOUNT_BASE}/${dev}"; then
            err "Test environment not set up: ${MOUNT_BASE}/${dev}"
            exit 1
        fi
        prepare_benchmark_file "${dev}"
    done

    stamp="$(date +%Y%m%d-%H%M%S)"
    output_dir="${TEST_DIR}/benchmark-${stamp}"
    mkdir -p "${output_dir}"
    log "Clean benchmark output: ${output_dir}"

    for ((round = 1; round <= rounds; round++)); do
        # Alternate device order to reduce systematic host writeback bias.
        if ((round % 2)); then
            dev_order=(plain aes)
        else
            dev_order=(aes plain)
        fi
        for dev in "${dev_order[@]}"; do
            for rw in randread randwrite; do
                sync
                echo 3 > /proc/sys/vm/drop_caches
                fio --name="${dev}_${rw}" \
                    --filename="${MOUNT_BASE}/${dev}/bench.dat" \
                    --rw="${rw}" --bs=4k --size="${BENCH_SIZE}" --direct=1 \
                    --ioengine=libaio --iodepth=1 --numjobs=1 --time_based=1 \
                    --runtime="${runtime}" --group_reporting=1 --output-format=json \
                    --output="${output_dir}/${dev}-${rw}-${round}.json"
                log "round=${round}/${rounds} dev=${dev} rw=${rw} complete"
            done
        done
    done

    {
        echo -e "device\toperation\tround\tiops\tmean_clat_us\tp99_clat_us"
        for dev in plain aes; do
            for rw in randread randwrite; do
                local op="${rw#rand}"
                for ((round = 1; round <= rounds; round++)); do
                    jq -r --arg dev "${dev}" --arg op "${op}" --arg round "${round}" \
                        '[ $dev, $op, $round,
                           .jobs[0][$op].iops,
                           (.jobs[0][$op].clat_ns.mean / 1000),
                           (.jobs[0][$op].clat_ns.percentile["99.000000"] / 1000) ] | @tsv' \
                        "${output_dir}/${dev}-${rw}-${round}.json"
                done
            done
        done
    } >"${output_dir}/summary.tsv"
    awk -F '\t' '
        NR == 1 { next }
        {
            key = $1 "\t" $2
            count[key]++
            iops[key] += $4
            mean[key] += $5
            p99[key] += $6
        }
        END {
            print "| device | operation | rounds | mean IOPS | mean clat (us) | mean P99 (us) |"
            print "|---|---|---:|---:|---:|---:|"
            for (key in count) {
                split(key, part, "\t")
                printf "| %s | %s | %d | %.1f | %.3f | %.3f |\n", \
                    part[1], part[2], count[key], iops[key] / count[key], \
                    mean[key] / count[key], p99[key] / count[key]
            }
        }
    ' "${output_dir}/summary.tsv" >"${output_dir}/summary.md"
    log "Benchmark complete: ${output_dir}/summary.tsv"
}

do_aes_benchmark() {
    local output="${2:-${TEST_DIR}/aes-benchmark-$(date +%Y%m%d-%H%M%S).txt}"
    require_cmds cryptsetup
    mkdir -p "$(dirname "${output}")"
    {
        echo "# cryptsetup AES-XTS memory benchmark"
        echo "# date: $(date --iso-8601=seconds)"
        for bits in 256 512; do
            for round in 1 2 3; do
                echo "key=${bits} round=${round}"
                cryptsetup benchmark --cipher aes-xts-plain64 --key-size "${bits}" | tail -2
            done
        done
    } | tee "${output}"
    log "AES benchmark complete: ${output}"
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
    require_root
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

    if [ "${dev}" = "aes" ]; then
        "${PROJECT_DIR}/cryptmon" >"${output_dir}/cryptmon.log" 2>&1 &
    else
        "${PROJECT_DIR}/cryptmon" -d "${backing}" >"${output_dir}/cryptmon.log" 2>&1 &
    fi
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
Usage: $0 COMMAND [arguments]

Commands:
  setup
  teardown
  status
  io
  benchmark [seconds] [rounds]
  aes-benchmark [output-file]
  trace [aes|plain] [read|write|randread|randwrite] [seconds]
EOF
}

case "${1:-}" in
    setup)    do_setup ;;
    teardown) do_teardown ;;
    status)   do_status ;;
    io)       do_io ;;
    benchmark) do_benchmark "$@" ;;
    aes-benchmark) do_aes_benchmark "$@" ;;
    trace)    do_trace "$@" ;;
    *)        usage; exit 1 ;;
esac
