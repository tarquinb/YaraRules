import "androguard"
import "file"
import "cuckoo"


rule PUA : Ozzie
{


	condition:
		androguard.certificate.sha1("c24d1b4c81226bad788c0d266bba520ec0d8c2f7") 
		
}