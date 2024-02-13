rule apple_program {
  meta:
	use_value = "1"
  strings:
	$program = /PROGRAM:[\w-]{1,64} /
condition:
	all of them
}