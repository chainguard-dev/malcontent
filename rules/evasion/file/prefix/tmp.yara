rule hidden_short_path_temp: high {
  meta:
    description = "hidden short path in a temp directory"

  strings:
    $crit                = /[\w\/\.]{0,32}\/tmp\/\.\w[\w\-\.]{0,2}/ fullword
    $not_network_manager = "org.freedesktop.NetworkManager"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_X11             = "/tmp/.X11-unix"
    $not_XIM             = "/tmp/.XIM-unix"
    $not_cpp             = "/tmp/.cpp.err"
    $not_ice             = "SESSION_MANAGER" fullword
    $not_md              = "/dev/.tmp.md.%d:%d:%d"

  condition:
    $crit and none of ($not*)
}
