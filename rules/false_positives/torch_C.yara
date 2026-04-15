rule torch_C_cpython: override {
  meta:
    description      = "torch/_C.cpython-*-linux-gnu.so"
    upx_elf_tampered = "medium"

  strings:
    $pytorch = "PyTorch"
    $torch_c = "torch._C"

  condition:
    filesize < 500MB and all of them
}
