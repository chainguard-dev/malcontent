rule tell_app_system_events: medium {
  meta:
    hash_2011_bin_kcd = "1ae8945732fa3aa6c59220a5b18abeb4e6a0f723c3bb0d3dbae3ad7c64541be1"

  strings:
    $system_events           = "tell application \"System Events\""
    $not_front               = "set frontmost"
    $not_copyright           = "Copyright"
    $not_voice               = "VoiceOver"
    $not_current_screensaver = "start current screen saver"

  condition:
    $system_events and none of ($not*)
}
