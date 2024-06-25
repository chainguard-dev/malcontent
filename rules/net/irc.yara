
rule irc_c_format : high {
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

rule irc_protocol : high {
  meta:
    pledge = "inet"
    description = "Uses IRC (Internet Relay Chat"
    credit = "Initially ported from https://github.com/jvoisin/php-malware-finder"
    hash_2024_ReverseShell_0_1_0 = "351e6ed52c0634e6ac534db5a0935e7beee7e50312c77cabb8494139fe4c3459"
    hash_2024_clients_shellclientsocketirc = "486149b6cb6a547791d55ae5860e80d23c56c14a8ea2e8984a9f72bd549c3093"
    hash_2023_Unix_Trojan_Tsunami_d3b5 = "d3b513cb2eb19aad50a0d070f420a5f372d185ba8a715bdddcf86437c4ce6f5e"
  strings:
    $join = "JOIN" fullword
    $mode = "MODE" fullword
    $nick = "NICK" fullword
    $notice = "NOTICE" fullword
    $part = "PART" fullword
    $pass = "PASS" fullword
    $ping = "PING" fullword
    $pong = "PONG" fullword
    $privmsg = "PRIVMSG" fullword
    $user = "USER" fullword
  condition:
    $nick and $user and 2 of them
}
