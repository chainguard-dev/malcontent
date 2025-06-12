rule php_image_include: critical {
  meta:
    description = "Includes PHP code from within a image file"
    credit      = "Inspired by DodgyPHP rule in php-malware-finder"

  strings:
    $php     = "<?php"
    $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/

    // https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/ErrorHandler/Resources/views/exception_full.html.php#L9
    // https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/ErrorHandler/Resources/assets/images/favicon.png.base64
    $not_symfony1 = "include('assets/images/favicon.png.base64')"
    $not_symfony2 = "<a href=\"https://symfony.com/doc/<?= Symfony\\Component\\HttpKernel\\Kernel::VERSION; ?>/index.html\">"

  condition:
    filesize < 5242880 and all of them and none of ($not*)
}

rule php_in_image: critical {
  meta:
    description = "Image file contains PHP code"
    credit      = "Inspired by DodgyPHP rule in php-malware-finder"

  strings:
    $gif  = { 47 49 46 38 ?? 61 }
    $png  = { 89 50 4E 47 0D 0A 1A 0A }
    $jpeg = { FF D8 FF E0 ?? ?? 4A 46 49 46 }
    $php  = "<?php"

  condition:
    ($gif at 0 or $png at 0 or $jpeg at 0) and $php
}
