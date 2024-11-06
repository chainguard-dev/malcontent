rule hidden_x11: high linux {
  meta:
    description = "may store content in /tmp/.X11-unix"
    ref         = "https://www.welivesecurity.com/2021/10/07/fontonlake-previously-unknown-malware-family-targeting-linux/"

  strings:
    $x11 = /\/tmp\/\.X11-unix.{1,16}/

  condition:
    filesize < 10MB and all of them
}
