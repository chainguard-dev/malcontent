rule elf_infector : high {
  meta:
    description = "Possible ELF file infector"
  strings:
	$f_chmod = "fchmod" fullword
	$f_exit = "exit" fullword
	$f_readdir = "readdir" fullword
	$f_fopen = "fopen" fullword
	$f_ftruncate = "ftruncate" fullword
	$f_closedir = "closedir" fullword
	$f_fork = "fork" fullword
	$f_unlink = "unlink" fullword
	$f_strdup = "strdup" fullword
	$f_strlen = "strlen" fullword
	$f_read = "read" fullword
	$f_fputs = "fputs" fullword
	$f_lseek = "lseek" fullword
	$f_fclose = "fclose" fullword
	$f_malloc = "malloc" fullword
	$f_opendir = "opendir" fullword
	$f_ioctl = "ioctl" fullword
	$f_execve = "execve" fullword
	$f_fileno = "fileno" fullword
	$f_getcwd = "getcwd" fullword
	$f_waitpid = "waitpid" fullword
	$f_tmpnam = "tempnam" fullword

	$f_access = "access" fullword
	$f_write = "write" fullword
	$f_free = "free" fullword
  condition:
    filesize < 200KB and $f_readdir and $f_write and $f_fopen and 24 of ($f*) in (1200..4096)
}

rule small_elf_infector : critical {
  meta:
    description = "Possible small ELF file infector"
  condition:
    filesize < 40KB and elf_infector
}

rule fake_ekploit_elf_infector : critical {
  meta:
    description = "Possible ELF file infector masquerading as an exploit"
  strings:
	$e1 = "spl0it"
	$e2 = "xploit"

	$s1 = "SSH"
	$s2 = "shellcode"
	$s3 = "execve"
	$s4 = "send_packet"
	$s5 = "setup_connection"
  condition:
    filesize < 40KB and elf_infector and any of ($e*) and any of ($s*)
}
