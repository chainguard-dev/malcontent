rule macos_screensaver_engine_ref: medium {
  meta:
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"

  strings:
    $pgrep       = "ScreenSaverEngine"
    $not_synergy = "_SYNERGY"

  condition:
    $pgrep and none of ($not*)
}
