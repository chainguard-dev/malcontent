rule ActiveXObject: medium windows {
  meta:
    description = "Create an ActiveX object"

  strings:
    $ActiveXObject = "ActiveXObject"

  condition:
    any of them
}
