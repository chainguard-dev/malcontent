rule daemon: medium {
  meta:
    description = "Run as a background daemon"

  strings:
    $ref  = /[\w\-]{0,8}[dD]aemon/
    $ref2 = /[dD]aemonize/ fullword

    $not_flush = "newFlushDaemon"

  condition:
    filesize < 20MB and any of them and none of ($not*)
}
