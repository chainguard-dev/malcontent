rule py_keylogger_exfil : high {
  meta:
    description = "listens for keyboard events and exfiltrates them"
	filetypes = "py"
  strings:
    $http = "http"
    $http_POST = /POST[ \/\w]{0,32}/
	$http_Discord = "Discord"
    $f_pynput = "pynput.keyboard"
	$f_key = "Key" fullword
	$f_listener = "Listener" fullword
  condition:
    filesize < 256KB and any of ($http*) and all of ($f*)
}
