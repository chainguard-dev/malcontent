rule bash_tcp: high {
  meta:
    description = "sends data via /dev/tcp (bash)"
    filetypes   = "application/x-sh,application/x-zsh"

  strings:
    $ref = /[\w \-\\<]{0,32}>"{0,1}\/dev\/tcp\/[\$\{\/\:\-\w\"]{0,32}/

  condition:
    $ref
}
