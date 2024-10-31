rule hostinfo_collector: high macos {
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
