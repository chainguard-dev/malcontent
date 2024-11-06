rule tun_tap: medium linux {
  meta:
    description = "accesses the TUN/TAP device driver"

  strings:
    $ref = "/dev/net/tun" fullword

  condition:
    any of them
}
