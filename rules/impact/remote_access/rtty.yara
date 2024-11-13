rule rtty_webshell: critical {
  meta:
    description = "rtty webshell"
    ref         = "https://github.com/zhaojh329/rtty"

  strings:
    $socat     = "RTTY_FILE_MAGIC" fullword
    $bin_bash  = "request_transfer_file" fullword
    $pty       = "login_path" fullword
    $not_usage = "rtty version" fullword

  condition:
    filesize < 1MB and 3 of them
}
