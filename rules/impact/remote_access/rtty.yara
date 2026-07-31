rule rtty_webshell: critical {
  meta:
    description = "rtty webshell"
    ref         = "https://github.com/zhaojh329/rtty"

  strings:
    $socat     = "RTTY_FILE_MAGIC" fullword
    $bin_bash  = "request_transfer_file" fullword
    $pty       = "login_path" fullword
    $not_usage = "rtty version" fullword

  // $not_usage marks the genuine rtty tool's version banner, so it must not be
  // selectable as one of the three matches.

  condition:
    filesize < 1MB and all of ($socat, $bin_bash, $pty) and none of ($not*)
}
