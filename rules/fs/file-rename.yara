rule rename : harmless {
	meta:
		syscall = "rename"
		pledge = "cpath"
	strings:
		$rename = "rename" fullword
		$renameat = "renameat" fullword
		$rename_file = "renameFile" fullword
	condition:
		any of them
}



rule ren : medium {
  meta:
    description = "deletes files"
  strings:
	$del = "rename" fullword
	$cmd_echo = "echo off"
	$cmd_powershell = "powershell"
  condition:
	filesize < 16KB and $del and any of ($cmd*)
}