private rule post_json {
  strings:
    $json             = "application/json"
    $POST             = "POST"
    $encode_stringify = "JSON.stringify"

  condition:
    $json and $POST and any of ($encode*)
}

rule possible_oauth_stealer: high {
  meta:
    description = "Possibly steals OAuth Credential stealer"

  strings:
    $o_google  = "googleapis.com/oauth2/v4/token"
    $o_google1 = "accounts.google.com/o/oauth2/auth"
    $o_google2 = "googleapis.com/oauth2/v1/userinfo"
    $o_gogle3  = "GMAIL_CLIENT_ID"
    $o_google4 = "GMAIL_SCOPES"
    $o_google5 = "offline" fullword
    $o_google6 = "code_verifier"

    $o_microsoft  = "graph.microsoft.com/v1.0/me"
    $o_microsoft1 = "login.microsoftonline.com/common/oauth2/v2.0/authorize"
    $o_microsoft2 = "O365_CLIENT_ID"
    $o_microsoft3 = "O365_SCOPES"
    $o_microsoft4 = "code_challenge" fullword
    $o_microsoft5 = "code_challenge_method"

  condition:
    filesize < 10MB and post_json and 5 of ($o*)
}

rule oauth_stealer: critical {
  meta:
    description = "Possibly steals OAuth Credentials"

  strings:
    $COMPUTERNAME = "COMPUTERNAME"
    $USERDOMAIN   = "USERDOMAIN"
    $ipinfo       = "ipinfo.io"

  condition:
    filesize < 1MB and possible_oauth_stealer and any of them
}
