#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUNTIME="${CRYPTMON_RUNTIME:-3}"
ROUNDS="${CRYPTMON_ROUNDS:-3}"
TRACE_RUNTIME="${CRYPTMON_TRACE_RUNTIME:-1}"
KEEP_ENV=0
SKIP_TRACE=0
CREATED_ENV=0

usage() {
    cat <<EOF
Usage: $0 [--runtime SECONDS] [--rounds N] [--trace-runtime SECONDS]
          [--skip-trace] [--keep-env]

Builds cryptmon, creates an isolated loop/dm-crypt test environment, runs
plain/AES fio benchmarks and the AES memory benchmark, optionally captures
four eBPF+blktrace workloads, and writes everything below test/run-TIMESTAMP.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime) RUNTIME="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        --trace-runtime) TRACE_RUNTIME="$2"; shift 2 ;;
        --skip-trace) SKIP_TRACE=1; shift ;;
        --keep-env) KEEP_ENV=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

for value in "${RUNTIME}" "${ROUNDS}" "${TRACE_RUNTIME}"; do
    [[ "${value}" =~ ^[1-9][0-9]*$ ]] || {
        echo "Runtime and round arguments must be positive integers" >&2
        exit 1
    }
done

# Re-enter through shell.nix once so all build and runtime tools share one PATH.
if [ -z "${IN_NIX_SHELL:-}" ]; then
    quoted=""
    printf -v quoted '%q ' "$0" --runtime "${RUNTIME}" --rounds "${ROUNDS}" \
        --trace-runtime "${TRACE_RUNTIME}"
    [ "${SKIP_TRACE}" -eq 1 ] && quoted+="--skip-trace "
    [ "${KEEP_ENV}" -eq 1 ] && quoted+="--keep-env "
    exec nix-shell --run "${quoted}"
fi

cd "${PROJECT_DIR}"
make
sudo -v

stamp="$(date +%Y%m%d-%H%M%S)"
run_dir="${PROJECT_DIR}/test/run-${stamp}"
mkdir -p "${run_dir}"

cleanup() {
    local rc=$?
    if [ "${CREATED_ENV}" -eq 1 ] && [ "${KEEP_ENV}" -eq 0 ]; then
        sudo -n env "PATH=${PATH}" bash "${SCRIPT_DIR}/test.sh" teardown || true
    fi
    exit "${rc}"
}
trap cleanup EXIT INT TERM

if sudo -n dmsetup info crypt_test_aes &>/dev/null ||
   mountpoint -q /mnt/crypt_test/aes || mountpoint -q /mnt/crypt_test/plain; then
    echo "Existing crypt_mon environment detected; refusing one-click setup." >&2
    echo "Run 'sudo env PATH=\"$PATH\" bash script/test.sh teardown' first." >&2
    exit 1
fi

{
    echo "date=$(date --iso-8601=seconds)"
    echo "kernel=$(uname -srvo)"
    echo "machine=$(uname -m)"
    echo "fio=$(fio --version)"
    echo "cryptsetup=$(cryptsetup --version)"
    lscpu
} >"${run_dir}/environment.txt"

sudo -n env "PATH=${PATH}" bash "${SCRIPT_DIR}/test.sh" setup
CREATED_ENV=1

sudo -n env "PATH=${PATH}" bash "${SCRIPT_DIR}/test.sh" benchmark \
    "${RUNTIME}" "${ROUNDS}"
bash "${SCRIPT_DIR}/test.sh" aes-benchmark "${run_dir}/aes-benchmark.txt"

# Record the benchmark directory created most recently by this run.
benchmark_dir="$(find "${PROJECT_DIR}/test" -maxdepth 1 -type d \
    -name 'benchmark-*' -newer "${run_dir}/environment.txt" | sort | tail -1)"
[ -n "${benchmark_dir}" ] && ln -s "../$(basename "${benchmark_dir}")" \
    "${run_dir}/benchmark"

if [ "${SKIP_TRACE}" -eq 0 ]; then
    for dev in aes plain; do
        for rw in randread randwrite; do
            sudo -n env "PATH=${PATH}" bash "${SCRIPT_DIR}/test.sh" trace \
                "${dev}" "${rw}" "${TRACE_RUNTIME}"
        done
    done
    find "${PROJECT_DIR}/test" -maxdepth 1 -type d -name 'trace-*' \
        -newer "${run_dir}/environment.txt" -printf '%f\n' | sort \
        >"${run_dir}/trace-directories.txt"
fi

sudo -n dmsetup table crypt_test_aes | tee "${run_dir}/dm-table.txt" >/dev/null
cp "${PROJECT_DIR}/doc/report.md" "${run_dir}/report-snapshot.md"

echo "Complete test finished: ${run_dir}"
echo "Environment cleanup: $([ "${KEEP_ENV}" -eq 1 ] && echo kept || echo automatic)"
