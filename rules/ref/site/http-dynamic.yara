rule http_dynamic : notable {
  meta:
	description = "URL that is dynamically generated"
  strings:
    $ref = /https*:\/\/%s[\/\w\.]{0,64}/
	$ref2 = "https://%@:%@%@"
  condition:
	any of them
}
