import "androguard"
import "file"
import "cuckoo"


rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samples"
		

	strings:
		$a = "sandrorat" nocase

	condition:
		$a
		
}