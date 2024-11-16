rule osascript_caller: medium {
  meta:
    description = "runs osascript"

  strings:
    $o_osascript          = "osascript" fullword
    $o_osascript_e        = "osascript -e"
    $o_display_dialog     = "display dialog"
    $o_with_hidden_answer = "with hidden answer"
    $o_default            = "default button \""

  condition:
    any of ($o*)
}

rule macho_osascript_caller: high {
  meta:
    description = "machO binary runs osascript"

  strings:
    $o_osascript_e = /osascript.{1,8}-e/
    $tell          = /tell application \"[\w \/]{1,64}\" to [\w ]{6,64}/

  condition:
    filesize < 2MB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and any of them
}
