rule tell_app_system_events: medium {
  meta:
    description = "controls screen via osascript"

  strings:
    $system_events           = "tell application \"System Events\""
    $not_front               = "set frontmost"
    $not_copyright           = "Copyright"
    $not_voice               = "VoiceOver"
    $not_current_screensaver = "start current screen saver"

  condition:
    $system_events and none of ($not*)
}
