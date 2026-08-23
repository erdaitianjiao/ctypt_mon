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
    pkg-config
  ];
  shellHook = "echo crypt_mon dev env ready";
}
