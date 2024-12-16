rule dynamic_hidden_path: medium {
  meta:
    description = "hidden path generated dynamically"
    ref         = "https://objective-see.org/blog/blog_0x73.html"

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

rule known_hidden_path: critical {
  meta:
    description = "known hidden file path"

  strings:
    $xl1      = /[a-z\/]{0,24}\/(var|usr|tmp|lib)\/[a-z\/]{0,24}\/\.Xl1[\w\_\-\.]{0,16}/
    $kde_root = /[a-z\/]{0,24}\/(var|usr|tmp|lib)\/[a-z\/]{0,24}\/\.kde-root[\w\_\-\.]{0,16}/

  condition:
    any of them
}

rule hidden_path: medium {
  meta:
    description = "hidden path in a system directory"

  strings:
    $ref = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.\w[\w\-\.]{0,16}/

  condition:
    $ref
}

rule hidden_short_path_system: high {
  meta:
    description = "hidden short path in a system directory"

  strings:
    $crit                = /[\w\/\.]{0,32}\/(usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.\w[\w\-\.]{0,2}/ fullword
    $not_network_manager = "org.freedesktop.NetworkManager"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_X11             = "/tmp/.X11-unix"
    $not_XIM             = "/tmp/.XIM-unix"
    $not_cpp             = "/tmp/.cpp.err"
    $not_pwd             = "/etc/.pwd.lock"

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

rule hidden_danger_path: high {
  meta:
    description = "hidden dangerous-looking path in a system directory"

  strings:
    $ref = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.shm/ fullword

  condition:
    $ref
}
