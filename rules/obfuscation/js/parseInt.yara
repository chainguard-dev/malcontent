rule js_const_func_obfuscation : high {
	meta:
		description = "javascript obfuscation (integer parsing)"
		filetypes = "javascript"
	strings:
		$const = "const "
		$function = "function("
		$return = "{return"
		$parseInt = "parseInt"

	condition:
		filesize < 256KB and #const > 16 and #function > 32 and #parseInt > 8 and #return > 32
}
