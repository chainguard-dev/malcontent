rule php_uploader: medium {
  meta:
    description = "PHP script that accepts requests and uploads content"

  strings:
    $php           = "<?php"
    $upload        = "Upload"
    $uploader      = "uploader"
    $x_post        = "_POST"
    $x_get         = "_GET"
    $copy          = "copy($"
    $not_microsoft = "Microsoft Corporation"

  condition:
    $php and $copy and any of ($upload*) and any of ($x_*) and none of ($not*)
}
