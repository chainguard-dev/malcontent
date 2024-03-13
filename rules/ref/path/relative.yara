
rule relative_path_val : notable {
  meta:
	description = "references and possibly executes relative path"
  strings:
	$ref = /\.\/[a-z]{2,16}/ fullword
  condition:
	$ref
}
