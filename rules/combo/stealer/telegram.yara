
rule telegram_passwords : high {
  meta:
    description = "gets passwords, makes HTTP requests, and uses Telegram"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2024_hCrypto_main_en = "4d4d52eed849554e1c31d56239bcf8ddc7e27fd387330f5ab1ce7d118589e5f3"
  strings:
    $c3 = "api.telegram.org"
    $h1 = "get("
    $h2 = "post("
    $h3 = "GET"
    $h4 = "POST"
    $h5 = "https://"
    $h6 = "x-www-form-urlencoded"
    $p1 = "password"
    $p2 = "Password"
    $p3 = "credentials"
    $p4 = "creds"
    $not_prometheus = "prometheus-operator"
    $not_telegram_configs = "WithTelegramConfigs"
  condition:
    filesize < 1MB and any of ($c*) and any of ($h*) and any of ($p*) and none of ($not*)
}

rule telegram_content : critical {
  meta:
    description = "finds files, uploads documents to Telegram"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2024_hCrypto_main_en = "4d4d52eed849554e1c31d56239bcf8ddc7e27fd387330f5ab1ce7d118589e5f3"
  strings:
    $hostname = "api.telegram.org"
	$sendDocument = "sendDocument" fullword
    $f_listdir = "os.listdir" fullword
    $f_open = "open(" fullword
  condition:
    filesize < 32KB and all of them
}

