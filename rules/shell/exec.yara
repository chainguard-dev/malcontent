rule calls_shell : notable {
  meta:
	description = "Executes a shell"
  strings:
	$sh_val = /\/bin\/sh[ \%\{\}\$\-\w\"\']{2,64}/
	$bash_val = /\/bin\/bash[ \%\{\}\$\-\w\"\']{2,64}/
  condition:
    filesize < 100MB and any of them
}
