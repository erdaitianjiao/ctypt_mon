{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    llvmPackages.clang-unwrapped
    llvmPackages.libclang
    llvmPackages.llvm
    bpftools
    libbpf
    elfutils
    zlib
    fio
    blktrace
    cryptsetup
    jq
    lvm2
    e2fsprogs
    util-linux
    pkg-config
  ];
  shellHook = "echo crypt_mon dev env ready";
}
