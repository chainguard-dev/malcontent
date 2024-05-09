
rule osascript_http_zipper : high {
  meta:
	description = "runs AppleScript, makes HTTP requests, zips files"
  strings:
	$ref = "osascript" fullword
	$readdir = "readdir" fullword
	$socket = "socket" fullword
	$http = "HTTP" fullword
	$zip = "zip_writer"
  condition:
	all of them
}
