rule hardcoded_onion : critical {
  meta:
	description = "Contains hardcoded TOR onion address"
  strings:
    $ref = /[a-z0-9]{56}\.onion/
  condition:
	$ref
}