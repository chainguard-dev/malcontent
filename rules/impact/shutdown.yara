rule shutdown_val: medium {
  meta:
    description            = "calls shutdown command"


  strings:
    $ref  = /shutdown -[\w ]{0,16}/
    $ref2 = "shutdown now"

  condition:
    any of them
}
