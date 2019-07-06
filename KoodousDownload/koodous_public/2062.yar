import "androguard"
import "file"
import "cuckoo"


rule MonTransitApps : safe
{
	

	condition:
		androguard.certificate.sha1("ee6bb0756a02113fd46f2c434a06ebd5d04ff639")
		
}