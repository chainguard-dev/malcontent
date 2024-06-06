rule PDF_with_Launch_Action_Function
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects the launch function within a PDF file. This function allows the document author to attach an executable file."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://blog.didierstevens.com/2010/03/29/escape-from-pdf/"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "a9fbb50dedfd84e1f4a3507d45b1b16baa43123f5ae98dae6aa9a5bebeb956a8"

	strings:
			
		$pdf_header = "%PDF-"
		$a = "<</S/Launch/Type/Action/Win<</F"
	condition:
			
		$pdf_header in (0..1024) and $a

}