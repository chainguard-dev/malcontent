rule xmrig: high {
  meta:
    description = "References XMRig, a high-performance cryptocurrency miner"

  strings:
    $ref  = "XMRig"
    $ref2 = "xmrig"

  condition:
    any of them
}
