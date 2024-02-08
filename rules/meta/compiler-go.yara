rule go {
  strings:
	$buildinfo = "go:buildinfo"
	$gostring = "_runtime.gostring"
condition:
	any of them
}
