import "androguard"

rule safe : PayU
{
	condition:
		
		androguard.certificate.sha1("bbb54a9135199f225e8a10e571d264a0e51601ef") 
		
}