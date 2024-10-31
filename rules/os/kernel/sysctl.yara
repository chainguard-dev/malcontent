rule sysctl: harmless {
  meta:
    description = "get or set kernel stat"

  strings:
    $sysctl = "sysctl"
    $Sysctl = "Sysctl"

  condition:
    any of them
}

