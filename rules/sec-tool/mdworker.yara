
rule mdworker : medium {
  meta:
    description = "references mdmorker, may masquerade as it on macOS"
    hash_2017_mdworker_sysmdworker = "0b62ac27fa0d666e46781dae372fceefd6f889c07dc7259a23dd39dc512a0a79"
  strings:
    $ref = "mdworker" fullword
  condition:
    $ref
}

rule mdworker_high : high {
  meta:
    description = "references mdmorker, may masquerade as it on macOS"
    hash_2017_mdworker_sysmdworker = "0b62ac27fa0d666e46781dae372fceefd6f889c07dc7259a23dd39dc512a0a79"
  strings:
    $ref = "mdworker" fullword
	$not_program = "@(#)PROGRAM:md"
	$not_proj = "PROJECT:Spotlight"
  condition:
    $ref and none of ($not*)
}
