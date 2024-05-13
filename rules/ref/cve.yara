
rule cve_mention {
  strings:
    $cve_re = /cve[-_]20[12]\d+-\d+/ nocase
    $not_xul = "XUL_APP_FILE"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_clang = "clang LLVM compiler"
    $not_deprecated = "DEPRECATED"
    $not_usage = "usage: " nocase
  condition:
    $cve_re and none of ($not*)
}
