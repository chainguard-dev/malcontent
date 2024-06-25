
rule vaguely_mirai_like_router_backdoor : critical {
  meta:
    description = "Resembles Mirai"
    hash_2024_downloaded_0a2a = "0a2a3b880826470de78131f845c90a3facb8dbf2cc5e7bde7262d8e834141e6d"
  strings:
    $ref1 = "/dev/null" fullword
    $ref2 = "/proc" fullword
    $ref3 = "socket" fullword
    $ref4 = "(null)" fullword
    $ref5 = "localhost"
    $ref6 = "<=>"
    $ref7 = "No XENIX semaphores available"
    $ref8 = "Unknown error"
    $ref9 = "Success"
    $not_strcmp = "strcmp"
    $not_libc = "libc" fullword
  condition:
    filesize < 122880 and 90% of ($ref*) and none of ($not*)
}

rule vaguely_gafygt : critical {
  meta:
    description = "Resembles GAFYGT"
    hash_2023_Linux_Malware_Samples_9e35 = "9e35f0a9eef0b597432cb8a7dfbd7ce16f657e7a74c26f7a91d81b998d00b24d"
    hash_2023_Linux_Malware_Samples_a385 = "a385b3b1ed6e0480aa495361ab5b5ed9448f52595b383f897dd0a56e7ab35496"
  strings:
    $ref1 = "/dev/null" fullword
    $ref4 = "(nul"
    $ref5 = "/bin/sh"
    $ref6 = "UDPRAW"
    $ref7 = "KILLBOT"
    $not_strcmp = "strcmp"
    $not_libc = "libc" fullword
  condition:
    filesize < 122880 and 90% of ($ref*) and none of ($not*)
}
