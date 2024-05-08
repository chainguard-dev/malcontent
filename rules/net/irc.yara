
rule irc : suspicious {
  meta:
    pledge = "inet"
    description = "Uses IRC (Internet Relay Chat"
    hash_2023_Unix_Trojan_Tsunami_8555 = "855557e415b485cedb9dc2c6f96d524143108aff2f84497528a8fcddf2dc86a2"
    hash_2023_Unix_Trojan_Tsunami_d3b5 = "d3b513cb2eb19aad50a0d070f420a5f372d185ba8a715bdddcf86437c4ce6f5e"
    hash_2023_Win_Trojan_Perl_9aed = "9aed7ab8806a90aa9fac070fbf788466c6da3d87deba92a25ac4dd1d63ce4c44"
  strings:
    $ref = "PRIVMSG"
    $ref2 = "NOTICE %s"
    $ref3 = "NICK %s"
    $ref4 = "JOIN %s :%s"
  condition:
    any of them
}
