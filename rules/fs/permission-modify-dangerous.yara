rule chmod_dangerous : notable {
  meta:
	description = "Makes a world writeable file"
  strings:
	$ref = /chmod [\-\w ]{0,4}666[ \$\w\/\.]{0,32}/
  condition:
	$ref
}

rule chmod_dangerous_exec : suspicious exfil {
  meta:
	description = "Makes a world writeable executable"
  strings:
	$ref = /chmod [\-\w ]{0,4}777[ \$\w\/\.]{0,32}/
  condition:
	$ref
}

