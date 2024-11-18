rule py_ssl {
  meta:
    description = "uses Python SSL library"

  strings:
    $ssl  = "import ssl" fullword
    $ssl2 = "ssl.create_default_context"

  condition:
    any of them
}
