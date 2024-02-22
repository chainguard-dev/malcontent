
rule rm_force {
  meta:
	description = "Forcibly deletes files using rm"
  strings:
	$ref = /rm [\-\w ]{0,4}-f[ \$\w\/\.]{0,32}/
  condition:
	$ref
}

