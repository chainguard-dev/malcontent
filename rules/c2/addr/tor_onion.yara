
rule hardcoded_onion : critical {
  meta:
    description = "Contains hardcoded TOR onion address"
    hash_2023_Unix_Ransomware_Ech0raix_01ef = "01efdb6d88d9d996a0a7c32e6f36e0563795073cc88fb239571abda498f34ef6"
    hash_2023_Unix_Ransomware_Ech0raix_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2023_Unix_Ransomware_Ech0raix_3d8d = "3d8d25e2204f25260c42a29ad2f6c5c21f18f90ce80cb338bc678e242fba68cd"
  strings:
    $ref = /[a-z0-9]{56}\.onion/
    $not_listen = "listen.onion"
  condition:
    $ref and none of ($not*)
}
