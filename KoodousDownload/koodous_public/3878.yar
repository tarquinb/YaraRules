import "androguard"
import "file"
import "cuckoo"


/*
6465780A30333500
*/
rule sorter_janus
{
	strings:
		$a = {64 65 78 0A 30}

	condition: 
		$a		
}