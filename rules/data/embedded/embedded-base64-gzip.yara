import "math"

rule base64_gz: medium {
  meta:
    description                                                                = "Contains base64 gzip content"
    hash_2023_Qubitstrike_branch_raw_mi                                        = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi                                                   = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2024_Deobfuscated_LocusShell_4fe93cfac7416fee810b7333ea4a6a513339429c = "8ffe7774d9bbd92c0e3674d52c8b8f37745cad8278c68be8685bcae76365e8e5"

  strings:
    $header = "H4sIA"

  condition:
    $header
}

rule base64_gz_small: high {
  meta:
    description = "Contains base64 gzip content"

  strings:
    $header             = "H4sIA"
    $not_assertEquals   = "assertEquals" fullword
    $not_test_case      = "test_case" fullword
    $not_gzipped_binary = "gzipped binary" fullword
    $not_example        = "H4sIAAAAAAAAAOlongstringtoken"

  condition:
    filesize < 32KB and $header and none of ($not*)
}

rule base64_gz_high_entropy: high {
  meta:
    description = "Contains base64 gzip content"

  strings:
    $header = "H4sIA"

  condition:
    filesize < 2MB and math.entropy(1, filesize) >= 5.0 and all of them
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
