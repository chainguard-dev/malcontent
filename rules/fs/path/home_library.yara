rule home_lib_path {
  meta:
    description = "path reference within ~/Library"

  strings:
    $resolv = /[\$\~][\w\/]{0,10}Library\/[ \w\/]{1,64}/

  condition:
    any of them
}

