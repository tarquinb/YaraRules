rule StartAll
{
	meta:
		description = "All Apps"

	strings:
		$a = "AndroidManifest.xml"
		
	condition:
		$a 
}