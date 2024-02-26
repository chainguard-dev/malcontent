rule service_start {
  strings:
    $ref = /service [\w\_\- ]{1,16} start/
	$not_osquery = "OSQUERY"
	$not_not_start = "service not start"
  condition:
	$ref and none of ($not*)
}