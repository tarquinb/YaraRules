import "androguard"
import "file"
import "cuckoo"


rule LeakerLocker2
{
	condition:
		androguard.service(/x\.u\.s/)
		
}