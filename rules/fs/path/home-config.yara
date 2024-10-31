rule home_config_path {
  meta:
    description = "path reference within ~/.config"

  strings:
    $resolv = /[\$\~\w\/]{0,10}\.config\/[ \w\/]{1,64}/

  condition:
    any of them
}

