rule rootshell: high {
  meta:
    description = "references a root shell"

  strings:
    $ref  = "rootshell"
    $ref2 = "r00tshell"

    $not_pypi_index = "testpack-id-lb001"

  condition:
    any of ($ref*) and none of ($not*)
}
