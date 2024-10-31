
rule references_com_apple_preferences_file : medium {
  meta:
    ref = "https://securelist.com/triangulation-validators-modules/110847/"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2022_CloudMensis_mdworker3 = "273633eee4776aef40904124ed1722a0793e6567f3009cdb037ed0a9d79c1b0b"
  strings:
    $com_apple_plist = /com\.apple\.[\w\-\.]{0,32}\.plist/
    $not_program = "@(#)PROGRAM:"
    $not_apple = "Copyright Apple Computer Inc"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_apple_internal = "internal to Apple Products"
    $not_microsoft = "Microsoft Corporation"
    $not_strict = "use strict"
    $not_speech_voice = "speech.voice"
    $not_apple_inc = "Apple Inc"
    $not_sandbox = "andbox profile"
    $not_postfix = "com.apple.postfixsetup.plist"
    $not_private_literal = "private-literal"
  condition:
    filesize < 157286400 and $com_apple_plist and none of ($not*)
}
