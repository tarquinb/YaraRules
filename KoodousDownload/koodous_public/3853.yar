import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "GitHub"

	strings:
		$a = "github.com"

	condition:
		$a or
		androguard.url(/github\.com/) or 
		cuckoo.network.dns_lookup(/github\.com/)
}