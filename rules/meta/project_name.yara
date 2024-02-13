rule apple_project {
  meta:
	use_value = "1"
  strings:
	$project = /PROJECT:.(\w\-){0,64}/
condition:
	all of them
}