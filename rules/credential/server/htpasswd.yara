rule htpasswd: medium {
  meta:
    description = "Access .htpasswd files"

  strings:
    $ref  = ".htpasswd"
    $ref2 = "Htpasswd"

  condition:
    any of them
}
