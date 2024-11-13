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
    $ref = /\/{0,1}var\/tmp\/\.[%\w\.\-\/]{0,64}/

    $not_xfs = "var/tmp/.fsrlast_xfs"

  condition:
    $ref and none of ($not*)
}

