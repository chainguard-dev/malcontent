rule tiny_copy_run_delete : critical {
  meta:
    description = "copy executable, run, and delete"
  strings:
	$cp = "cp -f"
	$rm = /rm [\-\w ]{0,4}f[ \$\w\/\.]{0,32}/
	$null = "/dev/null"
	$path_tmp = "/tmp"
	$path_bin = "/bin"
	$path_var = "/var/"
	$path_dev_shm = "/dev/shm"
	$run_quoted = /\"\$[\w\-\/\$]{1,12}\"/ fullword
	$run_dot_slash = /\.\/[\-\w\$]{1,12}/ fullword
	$run_absolute = /&& \/[\w\/\.]{0,32}/ fullword
  condition:
    filesize < 512 and $cp and $rm and $null and any of ($path*) and any of ($run*)
}

