rule sandrorat
{
	meta:
		description = ""
		
	strings:
		$a = "sandrorat" nocase

	condition:
		$a
		
}