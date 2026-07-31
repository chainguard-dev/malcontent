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
    // The whole $not set was added at once for a single Capture One compiled AppleScript;
    // "saving" and "display alert" are ordinary AppleScript vocabulary on their own, so
    // require the complete set before suppressing.
    filesize < 1048576 and all of ($s_*) and not all of ($not*)
}
