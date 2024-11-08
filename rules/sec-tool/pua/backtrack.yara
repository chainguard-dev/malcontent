rule pua_backtrack_keylogger: macos high {
  meta:
    description = "Backtrack Keylogger"

  strings:
    $modesitt     = "Modesitt Software"
    $modesitt_web = "www.modesittsoftware"
    $backtrack    = "BackTrack"

  condition:
    $backtrack and ($modesitt or $modesitt_web)
}
