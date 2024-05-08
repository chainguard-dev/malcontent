
rule osascript_caller : notable {
  strings:
    $o_osascript = "osascript" fullword
    $o_osascript_e = "osascript -e"
    $o_display_dialog = "display dialog"
    $o_with_hidden_answer = "with hidden answer"
    $o_default = "default button \""
  condition:
    any of ($o*)
}
