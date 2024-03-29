
rule py_lib_alias_val : notable {
	meta:
		description = "aliases core python library to an alternate name"
	strings:
		$val = /from \w{2,16} import \w{2,16} as \w{1,32}/ fullword
	condition:
		$val
}