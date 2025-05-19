rule compiled_osascript: medium {
  meta:
    description = "compiled osascript"
    filetypes   = "scpt,scptd"

  strings:
    $s_sysoexec        = "sysoexecTEXT"
    $s_aevtoapp        = "aevtoappnull"
    $not_capture_one   = "Capture One"
    $not_display_alert = "display alert"
    $not_saving        = "saving"
    $not_captureone    = "captureone"

  condition:
    filesize < 1048576 and all of ($s_*) and none of ($not*)
}
