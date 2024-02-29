rule generic_perl_socket_exec {
  meta:
    hash_2017_Perl_FruitFly_A = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_1980_FruitFly_A_9968 = "9968407d4851c2033090163ac1d5870965232bebcfe5f87274f1d6a509706a14"
    hash_2017_Perl_FruitFly_afpscan = "bbbf73741078d1e74ab7281189b13f13b50308cf03d3df34bc9f6a90065a4a55"
    hash_2017_Perl_FruitFly_quimitchin = "ce07d208a2d89b4e0134f5282d9df580960d5c81412965a6d1a0786b27e7f044"
    hash_2017_trojan_Perl_AFL = "cee71a5425a4cd7c0ca2fc6763d59f94dd11192b78cd696adc56c553174d5727"
    hash_2017_Perl_FruitFly_spaud = "befa9bfe488244c64db096522b4fad73fc01ea8c4cd0323f1cbdee81ba008271"
    hash_2023_uacert_socket = "912dc3aee7d5c397225f77e3ddbe3f0f4cf080de53ccdb09c537749148c1cc08"
    hash_2023_Win_Trojan_Perl_9aed = "9aed7ab8806a90aa9fac070fbf788466c6da3d87deba92a25ac4dd1d63ce4c44"
  strings:
	$perl = "perl"
    $socket_inet = "IO::Socket::INET"
    $socket = "use Socket"
    $and_exec = "exec"
    $and_system = "system("
    $and_backtick = "`;"
    $not_nuclei = "NUCLEI_TEMPLATES"
    $not_kitten = "KITTY_KITTEN_RUN_MODULE"
  condition:
    filesize < 1MB and $perl and any of ($socket*) and any of ($and_*) and none of ($not_*)
}