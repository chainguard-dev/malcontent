rule microsoft_oauth2: medium {
  meta:
    description = "exchanges credentials with Microsoft Office 365"

  strings:
    $o_microsoft1 = "login.microsoftonline.com/common/oauth2/v2.0/authorize"

  condition:
    any of them
}
