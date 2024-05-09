
rule xmrig : high {
  meta:
    description = "References XMRig, a high-performance cryptocurrency miner"
    hash_2023_Multios_Coinminer_Miner_6f28 = "6f2825856a5ae87face1c68ccb7f56f726073b8639a0897de77da25c8ecbeb19"
    hash_2023_Py_Trojan_NecroBot_0e60 = "0e600095a3c955310d27c08f98a012720caff698fe24303d7e0dcb4c5e766322"
    hash_2023_gcclib_xfitaarch = "163f78541c2fbdad128997534ecc2ad31b112f779347c526dd4e071a608de85c"
  strings:
    $ref = "XMRig"
    $ref2 = "xmrig"
  condition:
    any of them
}
