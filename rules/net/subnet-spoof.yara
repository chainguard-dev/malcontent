rule subnet_spoof: harmless {
  meta:
    description = "Spoofs network packets"
    syscall     = "setsockopt"

  strings:
    $subnet = "subnet"
    $spoof  = "spoof"

  condition:
    all of them
}
