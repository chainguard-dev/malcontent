rule lib_subdir: high linux {
  meta:
    description = "hides paths within a /lib subdirectory"

  strings:
    $ref = /\/lib\/[\w\.]{1,16}\/\.[\w\-\%\@]{1,16}/ fullword

  condition:
    any of them
}

rule hidden_library: high {
  meta:
    description                        = "hidden path in a Library directory"
    hash_2018_Calisto                  = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2020_MacOS_TinkaOTP           = "90fbc26c65e4aa285a3f7ee6ff8a3a4318a8961ebca71d47f51ef0b4b7829fd0"

  strings:
    $hidden_library = /\/Library\/\.\w{1,128}/
    $not_dotdot     = "/Library/../"
    $not_private    = "/System/Library/PrivateFrameworks/"

  condition:
    $hidden_library and none of ($not*)
}
