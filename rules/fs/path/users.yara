rule home_path: medium {
  meta:
    description = "references path within /Users"

  strings:
    $ref = /\/Users\/[\$\(\)%\w\.\-\/]{0,64}/

  condition:
    $ref
}
