rule cve_mention: medium {
  meta:
    description = "Mentions a recent CVE"

  strings:
    $cve_re         = /cve[-_]20[12]\d+-\d+/
    $CVE_re         = /CVE[-_]20[12]\d+-\d+/
    $not_xul        = "XUL_APP_FILE"
    $not_node       = "NODE_DEBUG_NATIVE"
    $not_clang      = "clang LLVM compiler"
    $not_deprecated = "DEPRECATED"
    $not_usage      = "usage: " nocase

  condition:
    ($cve_re or $CVE_re) and none of ($not*)
}

rule poc_mention: high {
  meta:
    description = "Mentions a recent CVE proof-of-concept"

  strings:
    $ref1 = /cve[-_]poc-20[12]\d+-\d+/
    $ref2 = /CVE[-_]POC-20[12]\d+-\d+/
    $ref3 = /poc[-_]cve-20[12]\d+-\d+/
    $ref4 = /POC[-_]CVE-20[12]\d+-\d+/

    $not_xul        = "XUL_APP_FILE"
    $not_node       = "NODE_DEBUG_NATIVE"
    $not_clang      = "clang LLVM compiler"
    $not_deprecated = "DEPRECATED"
    $not_usage      = "usage: " nocase

  condition:
    any of ($ref*) and none of ($not*)
}
