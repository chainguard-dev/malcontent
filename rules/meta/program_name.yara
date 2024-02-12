rule apple_program {
  strings:
	$program = /PROGRAM:[\w-]{1,64} /
condition:
	all of them
}