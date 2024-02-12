rule inotify {
  meta:
	description = "monitors filesystem events"
  strings:
	$ref = "inotify" fullword
  condition:
	any of them
}
