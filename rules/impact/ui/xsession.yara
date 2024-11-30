rule xsession: medium {
  meta:
    description = "makes references to Xsession"

  strings:
    $cookie = "Xsession"

  condition:
    any of them
}

