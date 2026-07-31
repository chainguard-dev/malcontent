rule hidden_short_path_temp: high {
  meta:
    description = "hidden short path in a temp directory"

  strings:
    $crit                = /[\w\/\.]{0,32}\/tmp\/\.\w[\w\-\.]{0,2}/ fullword
    $not_network_manager = "org.freedesktop.NetworkManager"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_ice             = "SESSION_MANAGER" fullword
    $not_md              = "/dev/.tmp.md.%d:%d:%d"

    // $crit matches each of these three verbatim, so a file that merely names
    // the X11 socket directory had every other hidden temp path in it
    // suppressed. Kept under their own prefix and compared by occurrence count
    // rather than presence: fire on any $crit hit they do not account for.
    $notpath_X11 = "/tmp/.X11-unix"
    $notpath_XIM = "/tmp/.XIM-unix"
    $notpath_cpp = "/tmp/.cpp.err"

  condition:
    $crit and #crit > #notpath_X11 + #notpath_XIM + #notpath_cpp and none of ($not_*)
}
