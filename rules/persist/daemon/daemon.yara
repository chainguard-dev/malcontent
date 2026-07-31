rule daemon: medium {
  meta:
    description = "Run as a background daemon"

  strings:
    $ref  = /[\w\-]{0,8}[dD]aemon/
    $ref2 = /[dD]aemonize/ fullword
    $word = /[dD]aemon/

    $not_flush = /[fF]lushDaemon/

  condition:
    // klog's flushDaemon/newFlushDaemon symbols are $ref matches, so any Go binary
    // linking klog used to lose every daemon reference in the file. $ref carries an
    // optional [\w\-]{0,8} prefix and reports one match per prefix length - nine for
    // a single "newFlushDaemon" - so it cannot be counted directly; count the bare
    // word instead. Each klog symbol contributes exactly one, so fire only on a
    // daemon reference klog does not account for. $ref2 stands on its own: klog has
    // no "daemonize".
    filesize < 20MB and ($ref2 or ($ref and #word > #not_flush))
}
