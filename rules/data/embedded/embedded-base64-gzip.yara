import "math"

rule base64_gz: medium {
  meta:
    description = "Contains base64 gzip content"

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
    $not_webpack   = "webpack-api-runtime.js" fullword

  condition:
    filesize < 2MB and math.entropy(1, filesize) >= 6.5 and $header and none of ($not*)
}

rule base64_obfuscated_js: high {
  meta:
    description = "Contains base64 gzip content within high-entropy javascript"

  strings:
    $f_header    = "H4sIA"
    $f_char_at   = "charAt("
    $f_substr    = "substr("
    $f_join      = "join("
    $f_function  = "function("
    $not_webpack = "webpack-api-runtime.js" fullword

  condition:
    filesize < 2MB and all of ($f*) and math.entropy(1, filesize) >= 5.0 and none of ($not*)
}
