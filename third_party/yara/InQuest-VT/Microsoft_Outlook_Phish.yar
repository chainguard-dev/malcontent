rule Microsoft_Outlook_Phish
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature fires on Phishing patterns detected within Microsoft Outlook messages (OLE)."
        created_date   = "2023-02-27"
        updated_date   = "2023-02-27"
        samples        = "09713976f2b6bf0b0cba3e10505293e313781c6b896fe0f772ea10ad83bf8435"

    strings:
        $ole_marker      = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/
        $phish_marker_00 = "eval(atob(atob("

        /* Generated via https://labs.inquest.net/tools/yara/b64-regexp-generator */
        /* [eE]nter [pP]assword */
        $phish_marker_01 = /([\x2b\x2f-9A-Za-z][02EGUWkm]VudGVyI[FH]Bhc3N3b3Jk|[\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx][Fl]bnRlciB[Qw]YXNzd29yZ[A-P]|[RZ]W50ZXIg[Uc]GFzc3dvcm[Q-T])/

        /* [fF]orgot [pP]assword */
        $phish_marker_02 = /([\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx][Gm]b3Jnb3Qg[Uc]GFzc3dvcm[Q-T]|[\x2b\x2f-9A-Za-z][02EGUWkm]ZvcmdvdCB[Qw]YXNzd29yZ[A-P]|[RZ]m9yZ290I[FH]Bhc3N3b3Jk)/

        /* [pP]rovide [pP]assword */
        $phish_marker_03 = /([Uc]HJvdmlkZSB[Qw]YXNzd29yZ[A-P]|[\x2b\x2f-9A-Za-z][13FHVXln]Byb3ZpZGUg[Uc]GFzc3dvcm[Q-T]|[\x2b\x2f-9A-Za-z]{2}[159BFJNRVZdhlptx][Qw]cm92aWRlI[FH]Bhc3N3b3Jk)/

    condition:
        $ole_marker at 0 and any of ($phish_marker_*) 
}
