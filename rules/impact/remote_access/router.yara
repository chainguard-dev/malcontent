rule vaguely_mirai_like_router_backdoor: critical {
  meta:
    description               = "Resembles Mirai"
    hash_2024_downloaded_0a2a = "0a2a3b880826470de78131f845c90a3facb8dbf2cc5e7bde7262d8e834141e6d"

  strings:
    $ref1       = "/dev/null" fullword
    $ref2       = "/proc" fullword
    $ref3       = "socket" fullword
    $ref4       = "(null)" fullword
    $ref5       = "localhost"
    $ref6       = "<=>"
    $ref7       = "No XENIX semaphores available"
    $ref8       = "Unknown error"
    $ref9       = "Success"
    $not_strcmp = "strcmp"
    $not_libc   = "libc" fullword

  condition:
    filesize < 122880 and 90 % of ($ref*) and none of ($not*)
}

rule vaguely_gafygt: critical {
  meta:
    description                          = "Resembles GAFYGT"
    hash_2023_Linux_Malware_Samples_9e35 = "9e35f0a9eef0b597432cb8a7dfbd7ce16f657e7a74c26f7a91d81b998d00b24d"
    hash_2023_Linux_Malware_Samples_a385 = "a385b3b1ed6e0480aa495361ab5b5ed9448f52595b383f897dd0a56e7ab35496"

  strings:
    $ref1       = "/dev/null" fullword
    $ref4       = "(nul"
    $ref5       = "/bin/sh"
    $ref6       = "UDPRAW"
    $ref7       = "KILLBOT"
    $not_strcmp = "strcmp"
    $not_libc   = "libc" fullword

  condition:
    filesize < 122880 and 90 % of ($ref*) and none of ($not*)
}

rule mirai_like: high linux {
  meta:
    description = "Mirai-like backdoor capabilities"
    filetypes   = "elf"
    ref         = "https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/"

  strings:
    $ = "/proc/%d"
    $ = "/proc/cpuinfo"
    $ = "/proc/self/fd"
    $ = "/proc/stat"
    $ = "/dev/null"
    $ = "getdents64" fullword
    $ = "environ" fullword
    $ = "fork" fullword
    $ = "fcntl" fullword
    $ = "open" fullword
    $ = "pagesize" fullword
    $ = "progname_full" fullword
    $ = "pthread_mutex_init" fullword
    $ = "srandom" fullword
    $ = "socket" fullword
    $ = "program_invocation_short_name" fullword
    $ = "mbsnrtowcs" fullword
    $ = "getsockname" fullword

  condition:
    uint32(0) == 1179403647 and filesize > 40KB and filesize < 95KB and 94 % of them
}
