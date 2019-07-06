rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samples"
		
	strings:
		$a = "SandroRat" 
		
	condition:
	
		$a
}