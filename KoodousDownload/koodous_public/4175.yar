import "androguard"
import "file"
import "cuckoo"


rule crypto : jcarneiro
{

	strings:
		$a = "xmr"

	condition:
		$a
		
}