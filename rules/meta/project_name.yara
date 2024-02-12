rule apple_project {
  strings:
	$project = /PROJECT:.(\w\-){0,64}/
condition:
	all of them
}