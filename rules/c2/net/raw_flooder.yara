
rule raw_flooder_val : medium {
  meta:
    description = "raw sockets with multiple targets, possible DoS or security scanning tool"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Linux_Malware_Samples_123e = "123e6d1138bfd58de1173818d82b504ef928d5a3be7756dd627c594de4aad096"
    hash_2023_Linux_Malware_Samples_14b8 = "14b898ab0df7209eb266b92684f1d68b15121304c17903b6b20789bf2345a4a0"
  strings:
    $r_raw = "raw socket"
    $r_hdr = "HDRINCL"
    $r_pack = "IPPacket"
    $f_flood = "flood"
    $f_target = "target"
    $f_Flood = "Flood"
    $f_Attack = "Attack"
    $p_pthread = "pthread"
    $p_rand = "rand" fullword
    $p_srand = "srand" fullword
    $p_gorand = "(*Rand).Intn"
  condition:
    any of ($r*) and any of ($f*) and any of ($p*)
}
