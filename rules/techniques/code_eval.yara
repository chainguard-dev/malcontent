rule eval : suspicious {
	meta:
		description = "evaluate code dynamically using eval()"
	strings:
		$ref = /eval\([\w\(\,\)]{0,32}/ fullword
	condition:
		any of them
}

