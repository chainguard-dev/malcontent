rule discord_password_post_chat: high {
  meta:
    description = "gets passwords, makes HTTP requests, and uses Discord"

    hash_2023_Qubitstrike_mi  = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"


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
