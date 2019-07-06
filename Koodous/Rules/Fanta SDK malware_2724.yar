import "androguard"
import "file"
import "cuckoo"


rule FantaSDK
{
	meta:
		author = "CP"
		date = "20-May-2017"
		description = "This rule detects the Fanta SDK malware see here http://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out"
		

	strings:
		$fanta_service = "com.fanta.services"
		$googie= "com.googie"
		$fantastr1 ="fanta\"" nocase
		$fantastr2 ="Fanta v." nocase
	condition:
		$fanta_service or $googie and ( $fantastr1 or $fantastr2 )
}