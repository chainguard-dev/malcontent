rule calls_shell : notable {
  meta:
	description = "Executes a shell"
  strings:
	$bin_sh = "/bin/sh"
	$bin_bash = "/bin/bash"
	$bin_dash = "/bin/dash"
	$bin_zsh = "/bin/zsh"
	// maybe even pull out a full command-line if we can
	$sh_val = /\/bin\/sh[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
	$bash_val = /\/bin\/bash[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
	$dash_val = /\/bin\/dash[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
	$zsh_val = /\/bin\/zsh[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
  condition:
    filesize < 100MB and any of them
}
