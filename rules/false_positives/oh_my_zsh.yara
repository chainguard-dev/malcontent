rule oh_my_zsh_diagnostics: override {
  meta:
    description             = "/usr/share/oh-my-zsh/lib/diagnostics.zsh"
    bash_logout_persist     = "low"
    zsh_logout_persist      = "low"
    bash_persist            = "low"
    bash_persist_persistent = "low"
    zsh_persist             = "low"

  strings:
    $omz_diag  = /omz_diagnostic_dump/
    $omz_inner = /_omz_diag_dump_one_big_text/

  condition:
    filesize < 20KB and all of them
}

rule oh_my_zsh_security_completion: override {
  meta:
    description            = "/usr/share/oh-my-zsh/plugins/macos/_security"
    security_dump_keychain = "low"

  strings:
    $compdef = /#compdef security/
    $list_kc = /list-keychains:Display or manipulate the keychain search list/

  condition:
    filesize < 10KB and all of them
}
