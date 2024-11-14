rule rootshell: high {
  meta:
    description            = "references a root shell"




  strings:
    $ref  = "rootshell"
    $ref2 = "r00tshell"

  condition:
    any of them
}
