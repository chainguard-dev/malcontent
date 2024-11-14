rule macos_screensaver_engine_ref: medium {
  meta:


  strings:
    $pgrep       = "ScreenSaverEngine"
    $not_synergy = "_SYNERGY"

  condition:
    $pgrep and none of ($not*)
}
