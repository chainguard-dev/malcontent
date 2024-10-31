rule echo_crontab: high {
  meta:
    hash_2020_Enigma     = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"
    hash_2024_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2024_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"

  strings:
    $echo = /echo.{0,10}\* \* \* \*.{0,24}cron[\w\/ \-]{0,16}/

  condition:
    $echo
}
