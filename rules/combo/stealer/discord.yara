
rule discord_password_post_chat : high {
  meta:
    description = "gets passwords, makes HTTP requests, and uses Discord"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2024_hCrypto_main_en = "4d4d52eed849554e1c31d56239bcf8ddc7e27fd387330f5ab1ce7d118589e5f3"
  strings:
    $c1 = "discordapp.com"
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
  condition:
    any of ($c*) and any of ($h*) and any of ($p*)
}
