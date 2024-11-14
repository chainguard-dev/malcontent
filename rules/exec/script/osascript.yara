rule osascript_caller: medium {
  meta:
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"

  strings:
    $o_osascript          = "osascript" fullword
    $o_osascript_e        = "osascript -e"
    $o_display_dialog     = "display dialog"
    $o_with_hidden_answer = "with hidden answer"
    $o_default            = "default button \""

  condition:
    any of ($o*)
}
