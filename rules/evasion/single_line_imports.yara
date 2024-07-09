
rule single_line_import : medium {
  meta:
    description = "imports built-in and executes more code on the same line"
  strings:
    $ref = /import [a-z0-9]{0,8};/
  condition:
	$ref
}


rule single_line_import_multiple : high {
  meta:
    description = "imports multiple built-ins on the same line"
  strings:
    $ref = /import [a-z0-9]{0,8}; {0,2}import [a-z0-9]{0,8}; {0,2}/
  condition:
	$ref
}

