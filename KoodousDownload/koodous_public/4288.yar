import "androguard"
import "file"
import "cuckoo"


rule reddrop2
{
	meta:
		description = "This rule detects malicious samples belonging to Reddrop campaign"
		sample = "76b2188cbee80fffcc4e3c875e3c9d25"

	strings:
		$a_1 = "pay"
		$a_2 = "F88YUJ4"
		

	condition:
		all of ($a_*)

		
}