rule dmesg {
  meta:
    description = "accesses the kernel log ring buffer"

  strings:
    $dmesg = "dmesg" fullword

  condition:
    any of them
}
