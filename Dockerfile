FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    bpftool gcc make linux-headers-amd64 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

CMD ["make"]
