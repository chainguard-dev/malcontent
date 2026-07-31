rule daemon: medium {
  meta:
    description = "Run as a background daemon"

  strings:
    $ref  = /[\w\-]{0,8}[dD]aemon/
    $ref2 = /[dD]aemonize/ fullword

    $not_flush = "newFlushDaemon"

  // klog's "newFlushDaemon" is a $ref match, so any Go binary linking klog used
  // to lose every daemon reference in the file - including "daemonize", which
  // "newFlushDaemon" cannot account for. Scope the exclusion to the reference it
  // explains: $ref2 fires on its own.
  // ($ref cannot be count-compared instead: its optional [\w\-]{0,8} prefix
  // reports one match per prefix length, nine for a single "newFlushDaemon".)

  condition:
    filesize < 20MB and ($ref2 or ($ref and none of ($not*)))
}
