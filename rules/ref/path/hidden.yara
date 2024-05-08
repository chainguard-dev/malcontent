
rule dynamic_hidden_path : notable {
  meta:
    description = "hidden path generated dynamically"
    ref = "https://objective-see.org/blog/blog_0x73.html"
  strings:
    $ref = /%s\/\.[a-z][\w-]{0,32}/
    $config = "%s/.config"
  condition:
    $ref and not $config
}

rule static_hidden_path {
  meta:
    description = "possible hidden file path"
  strings:
    $ref = /\/[a-z]{3,10}[\w\/]{0,24}\/\.\w[\w\_\-\.]{0,16}/
  condition:
    $ref
}

rule hidden_path {
  meta:
    description = "hidden path in a system directory"
  strings:
    $crit = /[\w\/\.]{0,32}\/(tmp|usr\/\w{0,8}|bin|lib|LaunchAgents|lib64|var|etc|shm|mqueue|spool|log|Users|Movies|Music|WebServer|Applications|Shared|Library|System)\/\.\w[\w\-\.]{0,16}/
    $not_network_manager = "org.freedesktop.NetworkManager"
    $not_X11 = "/tmp/.X11-unix"
    $not_cpp = "/tmp/.cpp.err"
    $not_factory = "/Library/.FactoryMacCheckEnabled"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_compdef = "#compdef"
    $not_kandji = "/tmp/.io.kandji.passport-did-boot"
    $not_cargo = "/.cargo"
    $not_sandbox_profile = "andbox profile"
  condition:
    $crit and none of ($not*)
}

rule hidden_library : suspicious {
  meta:
    description = "hidden path in a Library directory"
  strings:
    $hidden_library = /\/Library\/\.\w{1,128}/
    $not_dotdot = "/Library/../"
    $not_private = "/System/Library/PrivateFrameworks/"
  condition:
    $hidden_library and none of ($not*)
}
