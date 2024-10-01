import "math"

rule child_process : critical {
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

		$a_const = "const "
		$a_function = "function("
		$a_return = "{return"

		$not_sw_bundle = "Recorded click position in absolute coordinates did not match the center of the clicked element."
		$not_sw_bundle2 = "This is likely due to a difference between the test runner and the trace viewer operating systems."
	condition:
		filesize < 128KB and all of ($a_*) and none of ($not_*)
}
