import "androguard"
import "file"
import "cuckoo"


rule crypto : jcarneiro
{

	strings:
		$a = "pool.minexmr.com"

	condition:
		$a
		
}