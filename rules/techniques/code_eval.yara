rule eval : suspicious {
	meta:
		description = "evaluate code dynamically using eval()"
	strings:
		$ref = /eval\([a-z\"\'\(\,\)]{1,32}/ fullword
		$empty = "eval()"
	condition:
		$ref and not $empty
}


rule python_exec : suspicious {
	meta:
		description = "evaluate code dynamically using exec()"
	strings:
		$ref = /exec\([a-z\"\'\(\,\)]{1,32}/ fullword
		$empty = "exec()"
	condition:
		$ref and not $empty
}
