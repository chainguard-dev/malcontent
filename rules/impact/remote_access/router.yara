rule vaguely_mirai_like_router_backdoor: critical {
  meta:
    description = "Resembles Mirai"

  strings:
    $ref1       = "/dev/null" fullword
    $ref2       = "/proc" fullword
    $ref3       = "socket" fullword
    $ref4       = "(null)" fullword
    $ref5       = "localhost"
    $ref7       = "No XENIX semaphores available"
    $ref8       = "Unknown error"
    $ref9       = "Success"
    $ref10      = "/sys/devices/system/cpu"
    $not_strcmp = "strcmp"
    $not_libc   = "libc" fullword

  condition:
    filesize > 50000 and filesize < 122880 and 88 % of ($ref*) and none of ($not*)
}

rule vaguely_gafygt: critical {
  meta:
    description = "Resembles GAFYGT"

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
