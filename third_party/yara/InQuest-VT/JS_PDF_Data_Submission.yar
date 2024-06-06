rule JS_PDF_Data_Submission
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects pdf files with http data submission forms. Severity will be 0 unless paired with Single Page PDF rule."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "a0adbe66e11bdeaf880b81b41cd63964084084a413069389364c98da0c4d2a13"

	strings:
			
        $pdf_header = "%PDF-"
        $js = /(\/JS|\/JavaScript)/ nocase
        $a1 = /app\s*\.\s*doc\s*\.\s*submitForm\s*\(\s*['"]http/ nocase
        $inq_tail = "INQUEST-PP=pdfparser"
	condition:		
        ($pdf_header in (0..1024) or $inq_tail in (filesize-30..filesize))
            and
        $js and $a1

}