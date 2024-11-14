import "math"

rule base64_gz: medium {
  meta:
    description                         = "Contains base64 gzip content"

    hash_2023_Qubitstrike_mi            = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

  strings:
    $header = "H4sIA"

  condition:
    $header
}

rule base64_gz_high_entropy: high {
  meta:
    description = "high entropy (>6.5), contains base64 gzip content"

  strings:
    $header        = "H4sIA"
    $not_cloudinit = "cloudinit" fullword

  condition:
    filesize < 2MB and math.entropy(1, filesize) >= 6.5 and $header and none of ($not*)
}

rule base64_obfuscated_js: critical {
  meta:
    description = "Contains base64 gzip content within high-entropy javascript"

  strings:
    $header = "H4sIA"
    $       = "charAt("
    $       = "substr("
    $       = "join("
    $       = "function("

  condition:
    filesize < 2MB and all of them and math.entropy(1, filesize) >= 5.0
}
