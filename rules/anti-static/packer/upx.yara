rule upx: high {
  meta:
    description = "Binary is packed with UPX"
    filetype    = "upx"

  strings:
    $u_upx_sig   = "UPX!"
    $u_packed    = "executable packer"
    $u_is_packed = "This file is packed"
    $not_upx     = "UPX_DEBUG_DOCTEST_DISABLE"

  condition:
    any of ($u*) in (0..1024) and none of ($not*)
}

rule upx_elf: high {
  meta:
    description = "Linux ELF binary packed with UPX"
    filetype    = "upx"

  strings:
    $proc_self      = "/proc/self/exe"
    $prot_exec      = "PROT_EXEC|PROT_WRITE failed"
    $not_upx_itself = "UPX comes with ABSOLUTELY NO WARRANTY"

  condition:
    uint32(0) == 1179403647 and $prot_exec and $proc_self and none of ($not*)
}

rule upx_elf_tampered: critical {
  meta:
    description = "Linux ELF binary packed with modified UPX"
    filetype    = "upx"

  strings:
    $prot_exec = "PROT_EXEC|PROT_WRITE failed"
    $upx       = "UPX!"

  condition:
    uint32(0) == 1179403647 and $prot_exec and not $upx
}
