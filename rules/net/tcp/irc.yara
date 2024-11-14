rule irc_protocol: medium {
  meta:
    pledge      = "inet"
    description = "Uses IRC (Internet Relay Chat)"
    credit      = "Initially ported from https://github.com/jvoisin/php-malware-finder"

  strings:
    $join    = "JOIN" fullword
    $mode    = "MODE" fullword
    $nick    = "NICK" fullword
    $notice  = "NOTICE" fullword
    $part    = "PART" fullword
    $pass    = "PASS" fullword
    $ping    = "PING" fullword
    $pong    = "PONG" fullword
    $privmsg = "PRIVMSG" fullword
    $user    = "USER" fullword

  condition:
    $nick and $user and 2 of them
}

rule small_elf_irc: high {
  meta:
    description = "Uses IRC (Internet Relay Chat)"

  condition:
    uint32(0) == 1179403647 and filesize < 10MB and irc_protocol
}
