rule malware_flubot_webshell {
     meta:
        description = "Webshell used in FluBot download page"
        author = "JPCERT/CC Incident Response Group"
        hash = "18f154adc2a1267b67d05ea125a3b1991c28651c638f0a00913d601c6237c2bc"

     strings:
        $token   = "aG1mN2ZkcXM5dmZ4cDhzNHJ3cXp4YmZ6NmM0M2J3Z2I="  // hmf7fdqs9vfxp8s4rwqzxbfz6c43bwgb
        $param01 = "Zm9yY2VfcmVkaXJlY3Rfb2ZmZXI="                  // force_redirect_offer
        $param02 = "c3ViX2lkXz"                                    // sub_id_
        $message01 = "RFctVkFMSUQtT0s="                            // DW-VALID-OK
        $message02 = "RFctSU5WQUxJRC1F"                            // DW-INVALID-E
        $message03 = "S1QtVkFMSUQtT0s="                            // KT-VALID-OK
        $message04 = "S1QtSU5WQUxJRC1F"                            // KT-INVALID-E

     condition:
       all of ($message*) or all of ($param*) or $token
}