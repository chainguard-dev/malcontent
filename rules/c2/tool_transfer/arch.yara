rule arch_ref: low {
  meta:
    description = "references a specific architecture"

  strings:
    $http  = "http://"
    $https = "https://"

    $a_AMD64  = "AMD64"
    $a_amd64  = "amd64"
    $a_x86    = "x86" fullword
    $a_x86_64 = "x86_64"
    $a_arm64  = "arm64"

  condition:
    any of ($http*) and any of ($a*)
}

rule multiple_arch_ref: low {
  meta:
    description = "references multiple architectures"

  strings:
    $http  = "http://"
    $https = "https://"

    $a_AMD64  = "AMD64"
    $a_amd64  = "amd64"
    $a_x86    = "x86" fullword
    $a_x86_64 = "x86_64"
    $a_arm64  = "arm64"

  condition:
    any of ($http*) and 2 of ($a*)
}
