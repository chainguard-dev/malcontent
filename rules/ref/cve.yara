
rule cve_mention {
  meta:
    hash_finspy_helper2 = "af4ad3b8bf81a877a47ded430ac27fdcb3ddd33d3ace52395f76cbdde46dbfe0"
    hash_2023_Linux_Malware_Samples_07d5 = "07d57c97f6af84f35a122b8a98f44242ac9da67f135cc337a88a231906cdece2"
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
