import "androguard"
import "file"
import "cuckoo"


rule mobby
{

	strings:
		$a = "io/mobby/sdk/receiver"
		$b = "io/mobby/sdk/activity"
		$c = "mobby"

	condition:
		any of them
		
}