rule obfuscate {
  meta:
    description = "Mentions the word obfuscate"

  strings:
    $obfuscate  = /obfuscate[\w]{0,32}/
    $not_ticket = "obfuscatedTicket"

  condition:
    $obfuscate and none of ($not*)
}

rule obfuscator {
  meta:
    description = "Mentions the word obfuscator"

  strings:
    $obfuscate = /[\w]{0,8}obfuscator/

  condition:
    $obfuscate
}

