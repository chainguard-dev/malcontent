rule Adobe_XMP_Identifier
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature identifies Adobe Extensible Metadata Platform (XMP) identifiers embedded within files. Defined as a standard for mapping graphical asset relationships, XMP allows for tracking of both parent-child relationships and individual revisions. There are three categories of identifiers: original document, document, and instance. Generally, XMP data is stored in XML format, updated on save/copy, and embedded within the graphical asset. These identifiers can be used to track both malicious and benign graphics within common Microsoft and Adobe document lures."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://wwwimages.adobe.com/content/dam/acom/en/products/xmp/Pdfs/XMPAssetRelationships.pdf"
        labs_reference = "https://labs.inquest.net/dfi/sha256/1030710f6f18950f01b1a55d50a5169717e48567aa13a0a769f5451423280b4d"
        labs_pivot     = "https://labs.inquest.net/dfi/search/ioc/xmpid/xmp.did%3AEDC9411A6A5F11E2838BB9184F90E845##eyJyZXN1bHRzIjpbIn4iLCJmaXJzdFNlZW4iLDEsIiIsW11dfQ=="
        samples        = "1030710f6f18950f01b1a55d50a5169717e48567aa13a0a769f5451423280b4d"

	strings:
    $xmp_md5  = /xmp\.[dio]id[-: _][a-f0-9]{32}/  nocase ascii wide
    $xmp_guid = /xmp\.[dio]id[-: _][a-f0-9]{36}/ nocase ascii wide
	condition:
			any of them
}
