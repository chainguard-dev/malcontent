rule obfuscate {
  meta:
	description = "Mentions the word obfuscate"
  strings:
    $obfuscate = /obfuscate[\w]{0,32}/
  condition:
	$obfuscate
}

rule obfuscator {
  meta:
	description = "Mentions the word obfuscator"
  strings:
    $obfuscate = /[\w]{0,8}obfuscator/
  condition:
	$obfuscate
}


