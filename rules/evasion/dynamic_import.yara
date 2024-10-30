rule dynamic_require: high {
  meta:
    description = "imports a library dynamically"
    filetypes   = "py"

  strings:
    $import  = "import" fullword
    $ref     = /require\(\w{2,16}\(.{0,64}\)/
    $not_str = "require(str("

  condition:
    $import and $ref and none of ($not*)
}

rule dynamic_require_decoded: critical {
  meta:
    description = "imports an obfuscated library dynamically"
    ref         = "https://blog.sucuri.net/2024/07/new-variation-of-wordfence-evasion-malware.html?ref=news.risky.biz"

  strings:
    $ref = /require\((strrev|base64_decode)\(.{0,64}\)/

  condition:
    $ref
}

rule dynamic_require_double_obscured: critical {
  meta:
    description = "imports an obfuscated library dynamically"

  strings:
    $ref = /require\(\w{0,16}\d\w{0,16}\(.{0,16}\d\w{0,16}/

  condition:
    $ref
}
