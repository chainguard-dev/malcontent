rule xmrig: high {
  meta:
    description = "References XMRig, a high-performance cryptocurrency miner"

    hash_2023_gcclib_xfitaarch = "163f78541c2fbdad128997534ecc2ad31b112f779347c526dd4e071a608de85c"

  strings:
    $ref  = "XMRig"
    $ref2 = "xmrig"

  condition:
    any of them
}
