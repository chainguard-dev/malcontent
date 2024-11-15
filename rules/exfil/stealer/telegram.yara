rule telegram_passwords: high {
  meta:
    description = "gets passwords, makes HTTP requests, and uses Telegram"

  strings:
    $c3                   = "api.telegram.org"
    $h1                   = "get("
    $h2                   = "post("
    $h3                   = "GET"
    $h4                   = "POST"
    $h5                   = "https://"
    $h6                   = "x-www-form-urlencoded"
    $p1                   = "password"
    $p2                   = "Password"
    $p3                   = "credentials"
    $p4                   = "creds"
    $not_prometheus       = "prometheus-operator"
    $not_telegram_configs = "WithTelegramConfigs"

  condition:
    filesize < 1MB and any of ($c*) and any of ($h*) and any of ($p*) and none of ($not*)
}

rule telegram_content: critical {
  meta:
    description = "finds files, uploads documents to Telegram"

  strings:
    $hostname     = "api.telegram.org"
    $sendDocument = "sendDocument" fullword
    $f_listdir    = "os.listdir" fullword
    $f_open       = "open(" fullword

  condition:
    filesize < 32KB and all of them
}

