
rule fakes {
	strings:
		$mozilla = "Mozilla/6.1 (compatible;" fullword
		$msie = "MSIE 9.0" fullword
	condition:
		any of them
}
