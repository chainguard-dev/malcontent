rule tell_app_system_events: medium {
  meta:
    hash_2011_bin_kcd        = "1ae8945732fa3aa6c59220a5b18abeb4e6a0f723c3bb0d3dbae3ad7c64541be1"
    hash_2017_MacOS_AppStore = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"
    hash_2017_MacOS_AppStore = "363d151d451a9687d5c0863933a15f7968d3d7018b26f6ba8df54dea9e2f635c"

  strings:
    $system_events           = "tell application \"System Events\""
    $not_front               = "set frontmost"
    $not_copyright           = "Copyright"
    $not_voice               = "VoiceOver"
    $not_current_screensaver = "start current screen saver"

  condition:
    $system_events and none of ($not*)
}
