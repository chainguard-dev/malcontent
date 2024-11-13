rule crypt_user: low {
  meta:
    description = "password encryption via crypt(3)"
    ref         = "https://man7.org/linux/man-pages/man3/crypt.3.html"

  strings:
    $ref = "crypt@@GLIBC"

  condition:
    any of them
}
