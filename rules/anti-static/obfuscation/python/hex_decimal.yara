rule python_hex_decimal: high {
  meta:
    description                  = "contains a large amount of escaped hex/decimal content"
	filetypes = "py"
  strings:
	$f_return = "return"
	$f_decode = "decode("
	$f_eval = "eval("
	$f_exec = "exec("

	$trash = /\\x{0,1}\d{1,3}\\/
  condition:
	filesize < 1MB and any of ($f*) and #trash in (filesize-1024..filesize) > 100
}
