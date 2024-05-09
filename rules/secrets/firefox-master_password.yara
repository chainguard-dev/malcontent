
rule firefox_master_password : high {
  meta:
    description = "Decrypts Firefox master password"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
  strings:
    $firefox = "Firefox"
    $nssPrivate = "nssPrivate"
  condition:
    all of them
}
