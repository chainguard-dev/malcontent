rule syscall: medium {
  meta:
    description = "directly invokes syscalls"

  strings:
	$ruby = "ruby" fullword
	$require = "require" fullword
    $syscall = /syscall \d{1,3}/

  condition:
    filesize < 64KB and any of ($r*) and $syscall
}
