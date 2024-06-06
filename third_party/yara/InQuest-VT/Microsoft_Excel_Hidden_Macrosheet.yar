rule Microsoft_Excel_Hidden_Macrosheet
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft Excel spreadsheets that contain hidden sheets. Presence of a hidden sheet alone is not indication of malicious behavior."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://support.office.com/en-us/article/hide-or-show-worksheets-or-workbooks-69f2701a-21f5-4186-87d7-341a8cf53344"
        labs_reference = "https://labs.inquest.net/dfi/sha256/127c67df5629ff69f67328d0c5c92c606ac7caebf6106aaee8364a982711c120"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Excel%20Macro%20Manipulates%20Hidden%20Sheets"
        samples        = "127c67df5629ff69f67328d0c5c92c606ac7caebf6106aaee8364a982711c120"

	strings:
			$ole_marker     = {D0 CF 11 E0 A1 B1 1A E1}
    $macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
    $macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}
    $hidden_xlsx_01 = /hidden\s*=\s*["'][12]["']/ nocase
    $hidden_xlsx_02 = /state\s*=\s*["'](very)?Hidden["']/ nocase
	condition:
			($ole_marker at 0 and 1 of ($macro_sheet_h*))
    or
	 any of ($hidden_xlsx*)
}
