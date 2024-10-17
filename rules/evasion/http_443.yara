rule http_port_443 : high {
  meta:
    description = "hardcoded HTTP site on port 443 (HTTPS)"
  strings:
	$http_443 = /http:\/\/[\w\.]{0,32}:443\/[\/\w\-\?\.]{0,32}/
  condition:
	any of them
}
