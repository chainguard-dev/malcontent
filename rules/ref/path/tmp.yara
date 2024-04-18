rule tmp_path : notable {
	meta:
		description = "path reference within /tmp"
	strings:
		$resolv = /\/tmp\/[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}


rule weird_tmp_path_not_hidden : notable {
  meta:
	description = "references an unusual path within /tmp"
    hash_2017_Dockster = "8da09fec9262d8bbeb07c4e403d1da88c04393c8fc5db408e1a3a3d86dddc552"
    hash_2017_FileCoder = "c9c7c7f1afa1d0760f63d895b8c9d5ab49821b2e4fe596b0c5ae94c308009e89"
    hash_1980_FruitFly_A_205f = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_1980_FruitFly_A_ce07 = "ce07d208a2d89b4e0134f5282d9df580960d5c81412965a6d1a0786b27e7f044"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2021_malxmr = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2021_trojan_Mirai_aspze = "341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a"
  strings:
    $tmp_digits = /\/tmp\/[\w]*\d{1,128}/
    $tmp_short = /\/tmp\/[\w\.\-]{1,3}[^\w\.\-]/
    $not_x11 = "/tmp/.X11"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_movie = "/tmp/myTestMovie.m4"
    $not_usage = "usage: "
    $not_invalid = "invalid command option"
    $not_brother = "/tmp/BroH9"
    $not_compdef = "#compdef"
    $not_c1 = "/tmp/CaptureOne"
	$not_openra = "/tmp/R8"
	$not_private_literal = "private-literal"
	$not_apple = "Apple Inc"
	$not_sandbox = "andbox profile"
  condition:
    any of ($t*) and none of ($not*)
}
