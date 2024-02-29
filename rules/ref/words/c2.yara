rule maybe_command_and_control : notable {
  meta:
	description = "Uses terms that may reference a command and control server"
    hash_2023_Linux_Malware_Samples_2c98 = "2c98b196a51f737f29689d16abeea620b0acfa6380bdc8e94a7a927477d81e3a"
    hash_2021_ANDR_miner_eomap = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
    hash_2023_Linux_Malware_Samples_3ffc = "3ffc2327a5dd17978f62c44807e5bf9904bcdef222012a11e48801faf6861a67"
    hash_2023_Linux_Malware_Samples_564a = "564a666d0a7efc39c9d53f5c6c4d95d5f7f6b7bff2dc9aa3c871f8c49650a99b"
    hash_2021_miner_andr_dzpsy = "64815d7c84c249e5f3b70d494791498ce85ea9a97c3edaee49ffa89809e20c6e"
    hash_2021_miner_andr_aouid = "876b30a58a084752dbbb66cfcc003417e2be2b13fb5913612b0ca4c77837467e"
    hash_2023_Linux_Malware_Samples_9cb4 = "9cb463404a95bc04ade046fe59e089c5c52fc4e0b2ab0e070f3c38a606518f32"
    hash_2023_Linux_Malware_Samples_9e8e = "9e8e79637b5d21c7e3500345da26a2a15f77034623f6d711967b3750417f7ce5"
  strings:
    $control_server = "control server"
    $c_and_c = "command & control"
    $c_remote_control = "remote_control"
    $hash = "#"
    $not_kolide = "KOLIDE_LAUNCHER_OPTION"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_kitty = "KITTY_KITTEN_RUN_MODULE"
    $not_okitty = "net.kovidgoyal.kitty"
    $not_vscode = "Visual Studio Code"
  condition:
    (any of ($c*) and none of ($not*)) and not $hash at 0
}
