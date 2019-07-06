import "androguard"
import "file"
import "cuckoo"


rule safe : Alitalia
{


	condition:
		
		androguard.certificate.sha1("e58eacbcb251314d8afcb5a267dd247c9311afd2") 
		
}