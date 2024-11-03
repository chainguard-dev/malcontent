rule probably_a_miner: high {
  meta:
    hash_2023_Multios_Coinminer_Miner_6f28 = "6f2825856a5ae87face1c68ccb7f56f726073b8639a0897de77da25c8ecbeb19"
    hash_2023_gcclib_xfitaarch             = "163f78541c2fbdad128997534ecc2ad31b112f779347c526dd4e071a608de85c"
    hash_2023_Sysrv_Hello_sys_x86_64       = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"

  strings:
    $argon     = "argon2d"
    $proc_self = "/proc/self"
    $numa      = "NUMA"

  condition:
    filesize < 10MB and all of them
}
