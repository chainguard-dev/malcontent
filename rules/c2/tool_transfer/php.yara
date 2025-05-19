rule php_copy_url: high {
  meta:
    ref       = "kinsing"
    filetypes = "php"

  strings:
    $php  = "<?php"
    $copy = /copy\([\'\"]http/

  condition:
    all of them
}
