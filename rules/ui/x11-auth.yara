
rule refs {
	strings:
		$cookie = "MIT-MAGIC-COOKIE-1" fullword
		$xauth = "xauth" fullword
	condition:
		any of them
}