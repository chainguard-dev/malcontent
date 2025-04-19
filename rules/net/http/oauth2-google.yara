rule google_oauth2: medium {
  meta:
    description = "exchanges credentials with Google"

  strings:
    $o_google  = /googleapis.com\/oauth2\/[\w\/]{0,64}/
    $o_google1 = "accounts.google.com/o/oauth2/auth"

  condition:
    any of them
}
