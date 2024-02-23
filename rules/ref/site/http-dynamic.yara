rule http_dynamic : notable {
  meta:
	description = "URL that is dynamically generated"
  strings:
    $ref = /https*:\/\/%s[\/\w\.]{0,64}/
  condition:
	$ref
}
