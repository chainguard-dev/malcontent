rule mdworker : suspicious {
  meta:
	description = "references mdmorker, may masquerade as it on macOS"
  strings:
	$ref = "mdworker" fullword
  condition:
	$ref
}