
rule opaque_binary : medium {
  meta:
    hash_2024_Downloads_309f = "309f399788b63f66cfa7b37ae1db5dced55a9e73b768a7f05ea4de553192eeb1"
    hash_2024_Downloads_52d3 = "52d3f9458cfc31b2b8b6a5abd2ad743e7a2bb2999442ee2a3de5e17805cfbacc"
    hash_2024_Downloads_690f = "690f29dd425f7415ecb50986aa26750960c39a0ca8a02ddfd37ec4196993bd9e"
  strings:
    $word_with_spaces = /[a-z]{2,} [a-z]{2,}/
    $not_gmon_start = "__gmon_start__"
    $not_usage = "usage:" fullword
    $not_usage2 = "Usage:" fullword
    $not_USAGE = "USAGE:" fullword
    $not_java = "java/lang"
  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and #word_with_spaces < 4 and none of ($not*)
}
