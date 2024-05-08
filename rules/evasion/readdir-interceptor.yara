
rule readdir_intercept : suspicious {
  meta:
    description = "userland rootkit designed to hide files"
    hash_2023_lib_pkit = "8faa04955eeb6f45043003e23af39b86f1dbfaa12695e0e1a1f0bc7a15d0d116"
    hash_2023_lib_pkitarm = "67de6ba64ee94f2a686e3162f2563c77a7d78b7e0404e338a891dc38ced5bd71"
    hash_2023_lib_skit = "427b1d16f16736cf8cee43a7c54cd448ca46ac9b573614def400d2d8d998e586"
  strings:
    $r_new65 = "readdir64" fullword
    $r_old64 = "_readdir64"
    $r_new32 = "readdir" fullword
    $r_old32 = "_readdir"
    $not_ld_debug = "LD_DEBUG"
    $not_libc = "getusershell"
  condition:
    uint32(0) == 1179403647 and all of ($r*) and none of ($not*)
}

rule readdir_intercept_source : suspicious {
  meta:
    description = "userland rootkit designed to hide files"
  strings:
    $declare = "DECLARE_READDIR"
    $hide = "hide"
  condition:
    all of them
}

rule lkm_dirent : suspicious {
  meta:
    description = "kernel rootkit designed to hide files"
    hash_2023_LQvKibDTq4_diamorphine = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"
  strings:
    $dirent = "linux_dirent"
    $Linux = "Linux"
  condition:
    all of them
}
