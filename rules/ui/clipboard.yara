
rule nspasteboard : medium macos {
  meta:
    ref = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"
    description = "access clipboard contents"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
    hash_1979_CloudChat_clip = "ef1c7d6651996a3dccee755630add52c3f04a6e474ad15a999e132cafbf83f18"
  strings:
    $pb1 = "NSPasteboard" fullword
    $pb2 = "pbpaste" fullword
    $lib = "golang.design/x/clipboard"
    $lib2 = "atotto/clipboard"
  condition:
    all of ($pb*) or any of ($lib*)
}
