import "androguard"
import "file"
import "cuckoo"


rule BankBot
{
	strings:
		$a = "/private/tuk_tuk.php"
		$b = "/set/tsp_tsp.php"

		
	condition:
		$a or $b
}