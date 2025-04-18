rule contains_base64: medium {
  meta:
    description = "Contains base64 content"

  strings:
    $directory   = "directory" base64
    $address     = "address" base64
    $html        = "html" base64
    $uname       = "uname" base64
    $select      = "select" base64
    $company     = "company" base64
    $CERTIFICATE = "CERTIFICATE" base64

  condition:
    any of them
}

rule contains_base64_technical: high {
  meta:
    description = "Contains base64 technical content"

  strings:
    $linux_gnu = "linux-gnu" base64

  condition:
    any of them
}

rule contains_base64_certificate: medium {
  meta:
    description = "Contains base64 CERTIFICATE"

  strings:
    $CERTIFICATE = "CERTIFICATE" base64

  condition:
    any of them
}
