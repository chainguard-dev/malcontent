rule sleep_rm_sh_pipe: high {
  meta:
    ref = "https://cert.gov.ua/article/6123309"

  strings:
    $s_sleep_time = /sleep \d{1,128}/
    $s_pipe_sh    = "| /bin/sh"
    $s_rm_rf      = "rm -rf"

  condition:
    filesize < 16KB and all of them
}

rule proc_mounts_dd_dev_zero: high {
  meta:
    description = "may wipe mounted drives"

  strings:
    $mounts    = "/proc/mounts"
    $dd        = "dd" fullword
    $dev_input = /if=\/dev\/(zero|urandom|random)/

  condition:
    @mounts < @dd and @dd < @dev_input and @dev_input - @mounts <= 256
}
