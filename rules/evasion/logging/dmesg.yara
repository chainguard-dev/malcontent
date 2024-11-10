rule dmesg_clear: critical linux {
  meta:
    description = "clears the kernel log ring buffer"

  strings:
    $ = "dmesg -C" fullword
    $ = "dmesg -c" fullword
    $ = "dmesg --clear" fullword
    $ = "dmesg --read-clear" fullword

  condition:
    filesize < 150MB and any of them
}
