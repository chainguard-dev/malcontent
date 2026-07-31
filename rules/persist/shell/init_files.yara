rule etc_shell_init_references {
  strings:
    // $etc_zprofile was a second copy of the "/etc/profile" literal, which made
    // the count comparison below unusable; it added no coverage of its own
    $etc_profile         = "/etc/profile"
    $etc_bash            = "/etc/bash"
    $etc_bash_completion = "/etc/bash_completion.d"
    $etc_zsh             = "/etc/zsh"
    $not_bash            = "BASH_ENV"
    $not_ksh             = "KSH_VERSION"
    $not_shell           = "OPTARG"
    $not_login           = "login shell"
    $not_zshopts         = "zshoptions"
    $not_zstyle          = "zstyle"
    $not_completion_bash = "completion bash"
    $not_autocompletion  = "autocompletion"
    $not_autocomplete    = "autocomplete"
    $notprof_source      = "source /etc/profile"
    $notprof_dot         = ". /etc/profile"

  condition:
    // "source /etc/profile" and ". /etc/profile" each contain a "/etc/profile"
    // match, so compare counts for that path: sourcing the system profile
    // cancels only its own occurrence and a second reference still registers.
    // The other init-file paths and the nine shell-completion markers are
    // unaffected and stay membership tests.
    (#etc_profile > #notprof_source + #notprof_dot or any of ($etc_bash*, $etc_zsh)) and none of ($not_*)
}
