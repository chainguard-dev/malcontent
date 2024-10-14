import "math"

private rule probably_js {
	strings:
		$f_function = /function\(\w{0,8}\)/
		$f_const = "const" fullword
		$f_return = "return" fullword
		$f_var = "var" fullword
    condition:
		filesize < 512KB and all of ($f*)
}

rule high_entropy : medium {
    meta:
        description = "high entropy javascript (>5.37)"
    condition:
		probably_js and math.entropy(1,filesize) >= 5.37
}

rule very_high_entropy : critical {
    meta:
        description = "very high entropy javascript (>7)"
    condition:
		probably_js and math.entropy(1,filesize) >= 7
}

