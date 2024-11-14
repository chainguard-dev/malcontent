rule register_kprobe: medium {
  meta:
    description                      = "registers a kernel probe (possibly kernel module)"



  strings:
    $ref = "register_kprobe"

  condition:
    any of them
}
