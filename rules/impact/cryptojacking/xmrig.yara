rule xmrig: high {
  meta:
    description = "References XMRig, a high-performance cryptocurrency miner"

  strings:
    $ref  = "XMRig"
    $ref2 = "xmrig"

  condition:
    any of them
}

rule xmrig_dropper: critical {
  meta:
    description = "drops a copy of XMRig"
    ref         = "https://codeberg.org/k0rn66/xmrdropper"

  strings:
    $ref   = "k0rn66"
    $ref2  = "xmrdrop"
    $xmrig = "xmrig"
    $xMRIG = "XMRIG"

  condition:
    any of ($r*) and any of ($x*)
}
