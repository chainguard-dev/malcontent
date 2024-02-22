rule hardcoded_onion : critical {
  meta:
	description = "Contains hardcoded TOR onion address"
  strings:
    $ref = /\w{56}\.onion/
  condition:
	$ref
}