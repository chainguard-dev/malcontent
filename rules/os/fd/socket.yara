rule inspects_opened_sockets: medium {
  meta:
    description = "inspects open file descriptors for sockets"

  strings:
    $ref  = "socket:[" fullword
    $ref2 = /\/proc\/[%{$][\w\}]{0,12}\/fd/

  condition:
    all of them
}
