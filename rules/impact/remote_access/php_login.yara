rule php_login {
  meta:
    description = "unusual PHP login/password check"

  strings:
    $md5        = /md5\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{32}['"]/ nocase
    $sha1       = /sha1\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*['"][0-9a-f]{40}['"]/ nocase
    $isset_pass = "isset($_REQUEST['pass'])"

  condition:
    any of them
}
