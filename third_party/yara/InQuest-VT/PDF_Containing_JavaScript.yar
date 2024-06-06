rule PDF_Containing_JavaScript
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects a PDF file that contains JavaScript. JavaScript can be used to customize PDFs by implementing objects, methods, and properties. While not inherently malicious, embedding JavaScript inside of a PDF is often used for malicious purposes such as malware delivery or exploitation."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "www.sans.org/security-resources/malwarefaq/pdf-overview.php"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c82e29dcaed3c71e05449cb9463f3efb7114ea22b6f45b16e09eae32db9f5bef"

	strings:
			
		$pdf_tag1 = /\x25\x50\x44\x46\x2d/
		$js_tag1  = "/JavaScript" fullword
		$js_tag2  = "/JS"		  fullword
	condition:
			
		$pdf_tag1 in (0..1024) and ($js_tag1 or $js_tag2)

}
