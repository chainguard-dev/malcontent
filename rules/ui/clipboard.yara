
rule nspasteboard : notable macos {
  meta:
    ref = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"
    description = "access clipboard contents"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
  strings:
    $pb1 = "NSPasteboard" fullword
    $pb2 = "pbpaste" fullword
    $lib = "golang.design/x/clipboard"
    $lib2 = "atotto/clipboard"
  condition:
    all of ($pb*) or any of ($lib*)
}
