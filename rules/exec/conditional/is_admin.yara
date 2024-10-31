rule is_user_an_admin: medium windows {
  meta:
    description = "checks if user is an admin"

  strings:
    $ref = "IsUserAnAdmin"

  condition:
    any of them
}
