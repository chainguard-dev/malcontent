rule var_tmp_path: medium {
  meta:
    description = "path reference within /var/tmp"

  strings:
    $resolv = /var\/tmp\/[%\w\.\-\/]{0,64}/

  condition:
    any of them
}

rule var_tmp_path_hidden: high {
  meta:
    description = "path reference to hidden file within /var/tmp"

  strings:
    // The leading slash is dropped so $ref matches once, not twice, per
    // occurrence, which lets its count be compared against the accepted spelling.
    $ref = /var\/tmp\/\.[%\w\.\-\/]{0,64}/

    $not_xfs = "var/tmp/.fsrlast_xfs"

  condition:
    // $ref generalises the accepted spelling and now matches it exactly once,
    // so the counts cancel 1:1: require a hidden /var/tmp path beyond xfsrestore's.
    $ref and #ref > #not_xfs
}
