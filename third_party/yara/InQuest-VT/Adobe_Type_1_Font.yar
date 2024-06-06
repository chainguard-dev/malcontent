rule Adobe_Type_1_Font
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects an Adobe Type 1 Font. The Type 1 Font Format is a standardized font format for digital imaging applications."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.iso.org/standard/54796.html"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "64f2c43f3d01eae65125024797d5a40d2fdc9c825c7043f928814b85cd8201a2"

	strings:
	        $pdf = "%PDF-"
	        $magic_classic = "%!FontType1-1."
            $magic_next_generation1 = /obj\s*<<[^>]*\/Type\s*\/Font[^>]*\/Subtype\s*\/Type1/
            $magic_next_generation2 = /obj\s*<<[^>]*\/Subtype\s*\/Type1[^>]*\/Type\s*\/Font/
	condition:
			$magic_classic in (0..1024) or ($pdf in (0..1024) and any of ($magic_next_generation*))
}