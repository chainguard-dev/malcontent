rule python_bluesscreen: high windows {
  meta:
    description = "causes a blue screne (crash)"

  strings:
    $bluescreen = "RtlAdjustPrivilege(19, 1,"

  condition:
    filesize < 256KB and any of them
}
