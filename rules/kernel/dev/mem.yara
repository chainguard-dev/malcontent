
rule mem : suspicious {
  meta:
    capability = "CAP_SYS_RAWIO"
    description = "access raw system memory"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_gcclib_xfitaarch = "163f78541c2fbdad128997534ecc2ad31b112f779347c526dd4e071a608de85c"
  strings:
    $val = "/dev/mem"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho = "_PATH_RWHODIR" fullword
  condition:
    $val and none of ($not*)
}

rule comsvcs_minidump : suspicious {
  meta:
    description = "dump process memory using comsvcs.ddl"
    author = "Florian Roth"
  strings:
    $ref = /comsvcs(\.dll)?[, ]{1,2}(MiniDump|#24)/
  condition:
    any of them
}
