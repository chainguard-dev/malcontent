rule gethostbyname {
  meta:
    description = "resolve network host name to IP address"
    pledge      = "inet"
    ref         = "https://linux.die.net/man/3/gethostbyname"

  strings:
    $gethostbyname2 = "gethostbyname" fullword

  condition:
    any of them
}

rule gethostbyname2 {
  meta:
    description = "resolve network host name to IP address"
    pledge      = "inet"
    ref         = "https://linux.die.net/man/3/gethostbyname2"

  strings:
    $gethostbyname2 = "gethostbyname2" fullword

  condition:
    any of them
}

rule cannot_resolve {
  meta:
    description = "resolve network host name to IP address"

  strings:
    $cannot_resolve = "cannot resolve"
    $resolveDNS     = "resolveDNS"
    $resolveDns     = "resolveDns"

  condition:
    any of them
}

rule net_hostlookup {
  meta:
    description = "resolve network host name to IP address"

  strings:
    $net_lookup = "net.hostLookup"
    $hostip     = "LookupHostIP"

  condition:
    any of them
}

rule nodejs: medium {
  meta:
    description = "resolve network host name to IP address"
    filetypes   = "js,ts"

  strings:
    $resolve = "resolve4" fullword

  condition:
    filesize < 512KB and any of them
}

rule go_resolve: medium {
  meta:
    description = "resolve network host name to IP address"
    filetypes   = "elf,go,macho"

  strings:
    $resolve = "LookupHost" fullword

  condition:
    any of them
}
