rule obfuscate {
  meta:
    description = "Mentions the word obfuscate"

  strings:
    $obfuscate  = /obfuscate[\w]{0,32}/
    $not_ticket = "obfuscatedTicket"

  condition:
    // $obfuscate is a generalisation that also matches the accepted spelling
    // "obfuscatedTicket" in full, so switching the rule off on that one Go TLS
    // field excused every other "obfuscate" mention in the file. Counting instead
    // requires an "obfuscate" occurrence the accepted spelling does not account
    // for: each "obfuscatedTicket" cancels exactly the one $obfuscate match that
    // starts at the same offset.
    #obfuscate > #not_ticket
}

rule obfuscator {
  meta:
    description = "Mentions the word obfuscator"

  strings:
    $obfuscate = /[\w]{0,8}obfuscator/

  condition:
    $obfuscate
}
