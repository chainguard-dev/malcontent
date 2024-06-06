rule reversed_function_names : critical {
	meta:
		description = "Contains function names in reverse"
		credit = "Initially ported from https://github.com/jvoisin/php-malware-finder"
    strings:
		$create_function = "create_function"
		$system = "metsys"
		$passthru = "urhtssap"
		$include = "edulcni"
		$shell_execute = "etucexe_llehs"
	condition:
		any of them
}
