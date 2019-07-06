rule sandrorat
{
	meta:
		description = "Example"
	strings:
		$a = "Sandro"
	condition:
		$a
		
}