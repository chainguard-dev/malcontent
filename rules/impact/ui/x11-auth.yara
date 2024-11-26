rule x11_refs: medium {
  meta:
    description = "X Window System client authentication"
    ref         = "https://en.wikipedia.org/wiki/X_Window_authorization"

  strings:
    $cookie = "MIT-MAGIC-COOKIE-1" fullword
    $xauth  = "xauth" fullword

  condition:
    any of them
}

