rule opaque_binary: medium {
  meta:
    description = "binary contains little text content"

  strings:
    $word_with_spaces = /[a-z]{2,} [a-z]{2,}/
    $not_gmon_start   = "__gmon_start__"
    $not_usage        = "usage:" fullword
    $not_usage2       = "Usage:" fullword
    $not_USAGE        = "USAGE:" fullword
    $not_java         = "java/lang"

  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and #word_with_spaces < 4 and none of ($not*)
}
