rule etc_resolv_conf {
  meta:
    description = "accesses DNS resolver configuration"

  strings:
    $resolv = "/etc/resolv.conf"

  condition:
    any of them
}
