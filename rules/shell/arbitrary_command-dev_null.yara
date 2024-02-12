rule cmd_dev_null : suspicious {
	meta:
		description = "Runs arbitrary commands redirecting output to /dev/null"
	strings:
		$ref = /"{0,1}%s"{0,1} {0,2}[12&]{0,1}> {0,1}\/dev\/null/
	condition:
		any of them
}
