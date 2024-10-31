rule macos_proxy_manipulator {
  strings:
    $n_networksetup      = "networksetup"
    $n_setwebproxy       = "-setwebproxy"
    $n_setsecurewebproxy = "-setsecurewebproxy"
    $not_networksetup    = "networksetup tool"

  condition:
    2 of ($n_*) and none of ($not*)
}
