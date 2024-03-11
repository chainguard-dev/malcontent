rule apple_program {
  meta:
  	description = "program name"
  strings:
	$program_val = /PROGRAM:[\w-]{1,64} /
condition:
	all of them
}