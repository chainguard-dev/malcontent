rule js_const_func_obfuscation : critical {
	meta:
		description = "javascript obfuscation (excessive const functions)"
	strings:
		$const = "const "
		$function = "function("
		$return = "{return"
	condition:
		filesize < 256KB and #const > 32 and #function > 48 and #return > 64
}
