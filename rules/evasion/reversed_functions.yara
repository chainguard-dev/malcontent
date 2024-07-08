rule reversed_function_names : critical {
	meta:
		description = "Contains function names in reverse"
		credit = "Initially ported from https://github.com/jvoisin/php-malware-finder"
    strings:
		$create_function = "create_function"
		$r_system = "metsys"
		$r_passthru = "urhtssap"
		$r_include = "edulcni"
		$r_shell_execute = "etucexe_llehs"
		$r_base64_decode = "edoced_46esab"
	condition:
		$create_function and any of ($r*)
}

rule strrev_short : medium {
	meta:
		description = "calls strrev on a short string"
	strings:
		$strrev = /strrev\(['"][\w\=]{0,5}]'"]\)/
	condition:
		$strrev
}