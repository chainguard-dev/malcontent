
rule raise_hard_error : medium windows {
  meta:
    description = "crashes (bluescreens) the machine"
	filetypes = "py,exe"
  strings:
	$crash = "NtRaiseHardError" fullword
  condition:
    filesize < 1MB and any of them
}
