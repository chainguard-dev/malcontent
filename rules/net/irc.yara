rule irc : suspicious {
	meta:
		pledge = "inet"
		description = "Uses IRC (Internet Relay Chat"
	strings:
		$ref = "PRIVMSG"
		$ref2 = "NOTICE %s"
		$ref3 = "NICK %s"
		$ref4 = "JOIN %s :%s"
	condition:
		any of them
}
