rule EPPlus_OOXML_Document
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Documents created with EPPlus software that has been observed being abused by threat actors to deliver malicious payloads.  These documents are being built without using the Microsoft Office suite of tools and have active VBA code within the document, which makes them interesting.  These files are not malicious by nature but rather another tool abused for nefarious purposes."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://blog.nviso.eu/2020/09/01/epic-manchego-atypical-maldoc-delivery-brings-flurry-of-infostealers/"
        labs_reference = "https://labs.inquest.net/dfi/sha256/f4bd263fa5a0ab82ea20fe6789f2e514a4644dc24fcc4c22af05266d0574c675"
        labs_pivot     = "N/A"
        samples        = "f4bd263fa5a0ab82ea20fe6789f2e514a4644dc24fcc4c22af05266d0574c675"

	strings:
		$opc = "[Content_Types].xml"
        $ooxml = "xl/workbook.xml"
        $vba = "xl/vbaProject.bin"
        $meta1 = "docProps/core.xml"
        $meta2 = "docProps/app.xml"
        $timestamp = {50 4B 03 04 ?? ?? ?? ?? ?? ?? 00 00 21 00}
	condition:
		uint32be(0) == 0x504B0304
        and ($opc and $ooxml and $vba)
        and not (any of ($meta*) and $timestamp)
}