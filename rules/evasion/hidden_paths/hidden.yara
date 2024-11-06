rule dynamic_hidden_path: medium {
  meta:
    description                          = "hidden path generated dynamically"
    ref                                  = "https://objective-see.org/blog/blog_0x73.html"
    hash_2023_Linux_Malware_Samples_3292 = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
    hash_2023_Linux_Malware_Samples_d2ff = "d2fff992e40ce18ff81b9a92fa1cb93a56fb5a82c1cc428204552d8dfa1bc04f"
    hash_2023_Linux_Malware_Samples_efa8 = "efa875506296d77178884ba8ac68a8b6d6aef24e79025359cf5259669396e8dd"

  strings:
    $ref    = /%s\/\.[a-z][\w-]{0,32}/
    $ref_py = /os.path.join\(\w{1,8}, \"\.\w{1,16}"\)/
    $config = "%s/.config"

  condition:
    any of ($ref*) and not $config
}

rule static_hidden_path: medium {
  meta:
    description = "possible hidden file path"

  strings:
    $ref = /\/[a-z]{3,10}[\w\/]{0,24}\/\.\w[\w\_\-\.]{0,16}/

  condition:
    $ref
}

rule hidden_path: medium {
  meta:
    description = "hidden path in a system directory"

  strings:
    $ref = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.\w[\w\-\.]{0,16}/

  condition:
    $ref
}

rule hidden_short_path: high {
  meta:
    description = "hidden short path in a system directory"

  strings:
    $crit                = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.\w[\w\-\.]{0,2}/ fullword
    $not_network_manager = "org.freedesktop.NetworkManager"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_X11             = "/tmp/.X11-unix"
    $not_cpp             = "/tmp/.cpp.err"

  condition:
    $crit and none of ($not*)
}

rule hidden_shell_script: high {
  meta:
    description = "hidden shell script"

  strings:
    $crit = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.\w.{0,32}\.sh/ fullword

  condition:
    $crit
}

rule hidden_danger_path: critical {
  meta:
    description = "hidden dangerous-looking path in a system directory"

  strings:
    $ref = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.shm/ fullword

  condition:
    $ref
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
