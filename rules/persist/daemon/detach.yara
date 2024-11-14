rule detach: medium {
  meta:
    description = "process detaches and daemonizes"

  strings:
    $ref  = /[\w\/]{0,16}xdaemon/
    $ref2 = /[\w\/]{0,16}go-daemon/
    $ref3 = "RunInBackground"

  condition:
    any of them
}
