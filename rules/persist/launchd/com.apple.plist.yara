rule references_com_apple_preferences_file: medium {
  meta:
    ref = "https://securelist.com/triangulation-validators-modules/110847/"

  strings:
    $com_apple_plist     = /com\.apple\.[\w\-\.]{0,32}\.plist/
    $not_program         = "@(#)PROGRAM:"
    $not_apple           = "Copyright Apple Computer Inc"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_apple_internal  = "internal to Apple Products"
    $not_microsoft       = "Microsoft Corporation"
    $not_strict          = "use strict"
    $not_speech_voice    = "speech.voice"
    $not_apple_inc       = "Apple Inc"
    $not_sandbox         = "andbox profile"
    $not_postfix         = "com.apple.postfixsetup.plist"
    $not_private_literal = "private-literal"

  condition:
    filesize < 157286400 and $com_apple_plist and none of ($not*)
}
