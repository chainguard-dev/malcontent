rule apple_program {
  strings:
	$program = /PROGRAM:.*? /
condition:
	all of them
}