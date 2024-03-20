rule firefox_history : suspicious {
	meta:
		description = "Accesses Firefox form history, which contains passwords"
	strings:
		$firefox = "Firefox"
		// shorter ref so that it is likely to match obfuscated binaries
		$formhist = "formhis"
		$cookie = "cookie"
		$cookie2 = "Cookie"
		$sqlite = "sqlite"
	condition:
		$firefox and ($formhist or ($sqlite and any of ($cookie*)))
}
