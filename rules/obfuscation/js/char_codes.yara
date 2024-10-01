import "math"

rule child_process : high {
	meta:
		description = "obfuscated javascript that relies on character manipulation"
		filetypes = "javascript"
	strings:
		$a_char = "charCodeAt"
		$a_charAt = "charAt"
		$a_toString = "toString"
		$a_length = "length"
		$a_fromCharCode = "fromCharCode"
		$a_shift = "shift"
		$a_push = "push"

		$const = "const "
		$function = "function("
		$return = "{return"

	condition:
		filesize < 128KB and all of them
}
