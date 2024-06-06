rule PDF_Launch_Action_EXE
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects PDF files that launch an executable upon being opened on a host machine. This action is performed by the Launch Action feature available in the PDF file format and is commonly abused by threat actors to execute delivered malware."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "cb5e659c4ac93b335c77c9b389d8ef65d8c20ab8b0ad08e5f850cc5055e564c3"

	strings:
			
        /* 8 0 obj
        <<
        /Type /Action
        /S /Launch
        /Win
        <<
        /F (cmd.exe)
        >>
        >>
        endobj

        */

        $magic01 = "INQUEST-PP=pdfparser"
        $magic02 = "%PDF"

        $re1 = /\x2fType[ \t\r\n]*\x2fAction/ nocase wide ascii
        $re2 = /obj[^\x3c\x3e]+<<[^\x3e]*\x2fS[ \t\r\n]*\x2fLaunch[^\x3c\x3e]*<<[^\x3e]*\x2fF[ \t\r\n]*\x28[^\x29]+\.exe[^\x29]*\x29/ nocase wide ascii
	condition:
			
        ($magic01 in (filesize-30 .. filesize) or $magic02 in (0 .. 10)) and all of ($re*)

}