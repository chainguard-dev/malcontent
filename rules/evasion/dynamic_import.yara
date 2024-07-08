rule dynamic_require : medium {
  meta:
    description = "imports a library dynamically"
 strings:
    $ref = /require\(\w{0,16}\(.{0,64}\)/
  condition:
    $ref
}

rule dynamic_require_decoded : critical {
  meta:
    description = "imports an obfuscated library dynamically"
	ref = "https://blog.sucuri.net/2024/07/new-variation-of-wordfence-evasion-malware.html?ref=news.risky.biz"
 strings:
    $ref = /require\((strrev|base64_decode)\(.{0,64}\)/
  condition:
    $ref
}
