rule hostinfo_collector_commands: high macos {
  meta:
    ref         = "https://www.bitdefender.com/blog/labs/new-macos-backdoor-written-in-rust-shows-possible-link-with-windows-ransomware-group/"
    description = "Collects detailed host information"

  strings:
    $sp        = "system_profiler"
    $ns        = "networksetup"
    $sysctl    = "sysctl"
    $launchctl = "launchctl"

  condition:
    3 of them
}

rule hostinfo_collector_api: high macos {
  meta:
    ref         = "https://www.sentinelone.com/labs/infect-if-needed-a-deeper-dive-into-targeted-backdoor-macos-macma/"
    description = "Collects extremely detailed host information"

  strings:
    $ = "AvailableMemory"
    $ = "CpuInfoAndModel"
    $ = "DiskFreeSpace"
    $ = "environ"
    $ = "getifaddrs"
    $ = "HardwareUUID"
    $ = "if_nametoindex"
    $ = "IOPlatformExpertDevice"
    $ = "IOPlatformUUID"
    $ = "IPAddress"
    $ = /Mac[aA]ddress/
    $ = "machdep.cpu.brand"
    $ = "NSUserName"
    $ = "SystemVersion"

  condition:
    60 % of them
}

rule hostinfo_collector_npm: critical {
  meta:
    description = "collects an unusual amount of host information"
    filetypes   = "js,ts"

  strings:
    $f_userInfo = "os.userInfo()"
    $f_homedir  = "os.homedir()"

    $a_ipify       = /ipify\.org{0,1}/
    $a_wtfismyip   = "wtfismyip"
    $a_iplogger    = "iplogger.org"
    $a_getjsonip   = "getjsonip"
    $a_ipconfig_me = "ifconfig.me"
    $a_icanhazip   = "icanhazip"
    $a_grabify     = "grabify.link"
    $a_ident_me    = "ident.me" fullword
    $a_showip_net  = "showip.net" fullword
    $a_ifconfig_io = "ifconfig.io" fullword
    $a_ifconfig_co = "ifconfig.co" fullword
    $a_ipinfo      = "ipinfo.io"
    $a_check_ip    = "checkip.amazonaws.com"

  condition:
    filesize < 512KB and 2 of ($f*) and any of ($a*)
}
