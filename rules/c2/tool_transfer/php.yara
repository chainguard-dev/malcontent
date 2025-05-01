rule php_copy_url: high {
  meta:
    ref       = "kinsing"
    filetypes = "text/x-php"

  strings:
    $php  = "<?php"
    $copy = /copy\([\'\"]http/

  condition:
    all of them
}
