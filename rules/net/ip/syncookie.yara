rule syn_cookie: medium {
  meta:
    description = "references SYN cookies, used to resist DoS attacks"
    ref         = "https://en.wikipedia.org/wiki/SYN_cookies"

  strings:
    $syncookie  = "syncookie"
    $syn_cookie = "syn_cookie"

  condition:
    any of them
}
