rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samles"
		
	strings:
		$a = "SandroRat" nocase
		
	condition:
		$a
}