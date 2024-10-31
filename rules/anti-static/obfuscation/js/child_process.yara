import "math"

rule child_process : critical {
	meta:
		description = "obfuscated javascript that calls external programs"
	strings:
		$f_const = "const" fullword
		$f_return = "return" fullword
		$f_var = "var" fullword
		$o_child_process = "child_process"
		$o_decode = "decode("
		$o_tostring = "toString("
		$o_from = ".from("
		$wtf_hex = /\w{4,16}\<\-0x\d{2,4}/
    condition:
		filesize < 1MB and all of them and math.entropy(1,filesize) >= 6
}
