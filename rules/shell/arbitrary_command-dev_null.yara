rule cmd_dev_null : notable {
	meta:
		description = "Runs arbitrary commands redirecting output to /dev/null"
	strings:
		$ref = /"{0,1}%s"{0,1} {0,2}[12&]{0,1}> {0,1}\/dev\/null/
  	    $ref2 = "\"%s\" >/dev/null"
	condition:
		any of them
}
