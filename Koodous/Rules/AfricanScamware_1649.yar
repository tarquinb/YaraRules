import "androguard"
import "file"
import "cuckoo"


rule AfricanScamware
{
	meta:
		description = "Detects scamware originating from Africa"
		family = "AfricanScamware"
		
	strings:
		$a = "http://5.79.65.207:8810"
		$b = "http://plus.google.com"
		
	condition:
		($a and $b)
		
}