rule torch_C_cpython: override {
  meta:
    description          = "torch/_C.cpython-*-linux-gnu.so"
    upx_elf_tampered     = "medium"
    upx_antiunpack_elf64 = "harmless"

  strings:
    $torch_stub   = "torch/csrc/stub.c"
    $libtorch_dep = "libtorch_python.so"

  condition:
    filesize < 500MB and all of them
}
