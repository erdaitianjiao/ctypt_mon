FROM debian:bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    bpftool gcc make linux-headers-amd64 pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN make clean && make

FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 libelf1 zlib1g fio blktrace cryptsetup jq \
    lvm2 e2fsprogs util-linux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cryptmon
COPY --from=build /build/cryptmon ./cryptmon
COPY --from=build /build/script ./script
COPY --from=build /build/doc ./doc
COPY --from=build /build/README.md ./README.md

# eBPF and loop/dm tests require host BTF plus privileged block-device access.
# For normal development, the Nix shell on the host is the recommended path.
CMD ["./cryptmon"]
