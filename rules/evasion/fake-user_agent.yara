
rule fakes {
	strings:
		$mozilla = "Mozilla/6.1 (compatible;" fullword
		$msie = "MSIE 9.0" fullword
		$ff = "Mozilla/4"
 	condition:
		any of them
}
