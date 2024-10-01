
rule single_line_import : medium {
  meta:
    description = "imports built-in and executes more code on the same line"
	filetypes = "python"
  strings:
    $ref = /import [a-z0-9]{0,8};/
  condition:
	filesize < 64KB and $ref
}

rule single_line_import_multiple : high {
  meta:
    description = "imports multiple built-ins on the same line"
	filetypes = "python"
  strings:
    $ref = /import [a-z0-9]{0,8}; {0,2}import [a-z0-9]{0,8}; {0,2}/
  condition:
	filesize < 64KB and any of them
}



rule single_line_import_multiple_comma : medium {
  meta:
    description = "imports multiple comma spearated built-ins"
	filetypes = "python"
  strings:
	$ref2 = /import \w{2,8},\w{2,8},\w{2,8},[\w,]{0,64}/
  condition:
	filesize < 64KB and any of them
}

