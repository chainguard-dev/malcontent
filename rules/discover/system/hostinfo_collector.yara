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
