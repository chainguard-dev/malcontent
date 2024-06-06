rule PDF_Launch_Function
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects the launch function within a PDF file. This function allows a document author to attach an executable file."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/PDF-launch-feature-abused-to-carry-zeuszbot/"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c2f2d1de6bf973b849725f1069c649ce594a907c1481566c0411faba40943ee5"

	strings:
			
		$pdf_header = "%PDF-"
		$launch = "/Launch" nocase

	condition:
			
		$pdf_header in (0..1024) and $launch

}
