rule etc_shell_init_references {
  strings:
    $etc_profile            = "/etc/profile"
    $etc_bash               = "/etc/bash"
    $etc_bash_completion    = "/etc/bash_completion.d"
    $etc_zprofile           = "/etc/profile"
    $etc_zsh                = "/etc/zsh"
    $not_bash               = "BASH_ENV"
    $not_ksh                = "KSH_VERSION"
    $not_shell              = "OPTARG"
    $not_login              = "login shell"
    $not_zshopts            = "zshoptions"
    $not_zstyle             = "zstyle"
    $not_source_etc_profile = "source /etc/profile"
    $not_dot_etc_profile    = ". /etc/profile"
    $not_completion_bash    = "completion bash"
    $not_autocompletion     = "autocompletion"
    $not_autocomplete       = "autocomplete"

  condition:
    any of ($etc*) and none of ($not*)
}
