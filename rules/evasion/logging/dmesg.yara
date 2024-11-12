rule dmesg_clear: high linux {
  meta:
    description = "clears the kernel log ring buffer"

  strings:
    $ = "dmesg -C" fullword
    $ = "dmesg -c" fullword
    $ = "dmesg --clear" fullword
    $ = "dmesg --read-clear" fullword

  condition:
    filesize < 100MB and any of them
}

rule dmesg_clear_override: override {
  meta:
    dmesg_clear = "medium"

  strings:
    $Kselftest = "Kselftest" fullword

  condition:
    any of them
}
