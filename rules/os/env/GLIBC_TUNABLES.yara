rule glibc_tunables: harmless {
  strings:
    $ref = "GLIBC_TUNABLES"

  condition:
    any of them
}
