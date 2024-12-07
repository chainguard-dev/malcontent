rule arch_ref: low {
  meta:
    description = "references a specific architecture"

  strings:
    $AMD64  = "AMD64"
    $amd64  = "amd64"
    $x86    = "x86" fullword
    $x86_64 = "x86_64"
    $arm64  = "arm64"

  condition:
    any of them
}

rule multiple_arch_ref: low {
  meta:
    description = "references multiple architectures"

  strings:
    $AMD64  = "AMD64"
    $amd64  = "amd64"
    $x86    = "x86" fullword
    $x86_64 = "x86_64"
    $arm64  = "arm64"

  condition:
    2 of them
}
