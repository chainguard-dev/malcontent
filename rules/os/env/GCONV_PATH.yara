rule gconv_path : low {
  meta:
    description = "references character conversion configuration"
  strings:
	$ref = "GCONV_PATH"
  condition:
	any of them
}

rule gconv_path_dot : high {
  meta:
	description = "overrides GCONV_PATH to the current directory"
  strings:
	$ref = "GCONV_PATH=."
  condition:
	any of them
}
