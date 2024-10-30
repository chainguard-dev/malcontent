rule unusual_redir: medium {
  strings:
    $s_redir_stdin    = " 0>&1"
    $s_redir_bash     = "bash 2>/dev/null"
    $s_redir_bash_all = "bash &>"
    $s_redir_sh_i     = "sh -i </tmp/p 2>&1"
    $s_sh_redir       = "sh > /dev/null 2>&1"
    $s_bash_redir     = "bash >/dev/null 2>&1"
    $s_tmp_and_null   = />\/tmp\/[\.\w]{1,128} 2>\/dev\/null/
    $not_shell_if     = "if ["
    $not_shell_local  = "local -a"

  condition:
    any of ($s*) and none of ($not*)
}

rule redirect_everything: high {
  meta:
    description = "redirects all shell output to /dev/null"

  strings:
    $exec_dev_null  = "exec &>/dev/null" fullword
    $exec_dev_null2 = "exec >/dev/null 2>/dev/null" fullword

  condition:
    any of them
}
