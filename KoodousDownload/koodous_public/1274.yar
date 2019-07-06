rule sandrorat
{
	meta:
		description = "This rule detects Sandrorat samples"

	strings:
		$a = "SandroRat"

	condition:
		$a		
}