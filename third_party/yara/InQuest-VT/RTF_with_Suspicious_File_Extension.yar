rule RTF_with_Suspicious_File_Extension
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects RTF files with an 'objdata' directive and a reference to a file extension deemed as executable."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://www.biblioscape.com/rtf15_spec.htm"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "14ab1a85b0d6791f15952da15706b7997dd6ebdbbc9aea816e90f6009feb4b3c"

	strings:
			// '{\rt' (note that full header is *NOT* required: '{\rtf1')
        $magic = "{\\rt"

        $objstuff = /\\obj(data|update)/

        $ext_00 = /2e[46]5[57]8[46]500/ nocase     // .exe\x00
        $ext_01 = /2e[57]3[46]3[57]400/ nocase     // .sct\x00
        $ext_02 = /2e[57]3[46]3[57]200/ nocase     // .scr\x00
        $ext_03 = /2e[46]2[46]1[57]400/ nocase     // .bat\x00
        $ext_04 = /2e[57]0[57]33100/    nocase     // .ps1\x00
        $ext_05 = /2e[46]3[46]f[46]d00/ nocase     // .com\x00
        $ext_06 = /2e[46]3[46]8[46]d00/ nocase     // .chm\x00
        $ext_07 = /2e[46]8[57]4[46]100/ nocase     // .hta\x00
        $ext_08 = /2e[46]a[46]1[57]200/ nocase     // .jar\x00
        $ext_09 = /2e[57]0[46]9[46]600/ nocase     // .pif\x00
        $ext_10 = /2e[57]6[46]2[57]300/ nocase     // .vbs\x00
        $ext_11 = /2e[57]6[46]2[46]500/ nocase     // .vbe\x00
	condition:
			$magic at 0 and $objstuff and any of ($ext*)
}
