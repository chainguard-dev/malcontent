rule tls_get_addr: medium {
  meta:
    description = "looks up memory addresses for thread local storage or linked libraries"
    ref         = "https://chao-tic.github.io/blog/2018/12/25/tls"

  strings:
    $val = "__tls_get_addr" fullword

  condition:
    any of them
}
