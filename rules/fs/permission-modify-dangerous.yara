rule chmod_dangerous_val : notable {
  meta:
	description = "Makes a world writeable file"
  strings:
	$ref = /chmod [\-\w ]{0,4}666[ \$\w\/\.]{0,32}/
  condition:
	$ref
}

rule chmod_dangerous_exec_val : suspicious exfil {
  meta:
	description = "Makes a world writeable executable"
  strings:
	$ref = /chmod [\-\w ]{0,4}777[ \$\w\/\.]{0,32}/

	$not_dev_shm = "chmod 1777 /dev/shm"
	$not_chromium = "CHROMIUM_TIMESTAMP"
  condition:
	$ref and not ($not_dev_shm and $not_chromium)
}

