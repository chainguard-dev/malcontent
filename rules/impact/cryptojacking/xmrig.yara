rule xmrig_url: high {
  meta:
    description = "contains URL for XMRig, a high-performance cryptocurrency miner"

  strings:
    $ref = /https{0,1}:\/\/.{0,128}\/xmrig-[\d\.]{4,8}-linux-static-[\w\.]{0,8}/

  condition:
    any of them
}

rule xmrig: high {
  meta:
    description = "References XMRig, a high-performance cryptocurrency miner"

  strings:
    $ref            = "XMRig"
    $ref2           = "xmrig"
    $not_pypi_index = "testpack-id-lb001"

  condition:
    any of them and none of ($not*)
}

rule xmrdrop: critical {
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
