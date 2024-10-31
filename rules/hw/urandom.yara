rule urandom: harmless {
  meta:
    description = "references /dev/urandom"

  strings:
    $urandom = "/dev/urandom" fullword

  condition:
    any of them
}
