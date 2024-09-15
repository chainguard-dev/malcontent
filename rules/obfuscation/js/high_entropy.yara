import "math"

private rule probably_js {
	strings:
		$f_const = "const" fullword
		$f_return = "return" fullword
		$f_var = "var" fullword
    condition:
		filesize < 1MB and all of ($f*)
}


rule mid_entropy : medium {
    meta:
        description = "high entropy javascript (>5)"
    condition:
		probably_js and math.entropy(1,filesize) >= 5.2
}

rule high_entropy : high {
    meta:
        description = "high entropy javascript (>6)"
    condition:
		probably_js and math.entropy(1,filesize) >= 6
}

rule very_high_entropy : critical {
    meta:
        description = "very high entropy javascript (>7)"
    condition:
		probably_js and math.entropy(1,filesize) >= 7
}

