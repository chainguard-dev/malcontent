rule ExecShellScript: medium {
  meta:
    description = "executes a shell script"

  strings:
    $ExecShell   = "ExecShellScript"
    $exec_shell  = "exec_shellscript"
    $exec_shell2 = "exec_shell_script"
    $execShell   = "execShellScript"
    $RunShell    = "RunShellScript"
    $runShell    = "runShellScript"
    $run_shell   = "run_shell_script"
    $run_shell2  = "run_shellscript"

  condition:
    any of them
}
