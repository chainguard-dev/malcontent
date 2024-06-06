rule Microsoft_Excel_with_Macrosheet
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft Excel spreadsheets that contain macrosheets."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://inquest.net/blog/2020/03/18/Getting-Sneakier-Hidden-Sheets-Data-Connections-and-XLM-Macros"
        labs_reference = "https://labs.inquest.net/dfi/sha256/00c7f1ca11df632695ede042420e4a73aa816388320bf5ac91df542750f5487e"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Autostarting%20Excel%20Macro%20Sheet"
        samples        = "00c7f1ca11df632695ede042420e4a73aa816388320bf5ac91df542750f5487e"

	strings:
			$magic1 = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
	$xls_stub = {09 08 10 00 00 06 05 00}
    $olemacrosheet = /(\x85\x00.{6,7}[\x01\x02]|Excel 4.0 Macros)/
    $xlsxmacrosheet = /Type\s*=\s*['"]https?:\/\/schemas.microsoft.com\/office\/20\d\d\/relationships\/xlMacrosheet['"]/ nocase
	condition:
			(($magic1 at 0 and $xls_stub) and $olemacrosheet)
    or
    ($xlsxmacrosheet)
}