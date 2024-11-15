rule raw_flooder_val: medium {
  meta:
    description = "raw sockets with multiple targets, possible DoS or security scanning tool"

  strings:
    $r_raw     = "raw socket"
    $r_hdr     = "HDRINCL"
    $r_pack    = "IPPacket"
    $f_flood   = "flood"
    $f_target  = "target"
    $f_Flood   = "Flood"
    $f_Attack  = "Attack"
    $p_pthread = "pthread"
    $p_rand    = "rand" fullword
    $p_srand   = "srand" fullword
    $p_gorand  = "(*Rand).Intn"

  condition:
    any of ($r*) and any of ($f*) and any of ($p*)
}
