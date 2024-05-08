
rule uac_bypass : suspicious {
  meta:
    description = "may bypass UAC (User Account Control)"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
  strings:
    $uacbypass = "uacbypass" fullword
    $delegate = "fodhelper" fullword
  condition:
    any of them
}
