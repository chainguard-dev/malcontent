rule home_path: medium {
  meta:
    description = "references path within /Users"

    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"

  strings:
    $ref = /\/Users\/[\$\(\)%\w\.\-\/]{0,64}/

  condition:
    $ref
}
