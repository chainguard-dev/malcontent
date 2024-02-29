rule pua_backtrack_keylogger : malware trojan {
  meta:
	description = "Backtrack Keylogger"
    hash_2013_BackTrack = "1996ddc461861c59034fae84a4db45788d9f3b3e809389d36800d194dab138bd"
  strings:
    $modesitt = "Modesitt Software"
    $modesitt_web = "www.modesittsoftware"
    $backtrack = "BackTrack"
  condition:
    $backtrack and ($modesitt or $modesitt_web)
}
