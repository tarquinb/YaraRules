import "androguard"
import "file"
import "cuckoo"


rule koodous
{
	condition:
		androguard.certificate.sha1("642258CF2F7A3B2E87ECDE51493E9E7286089091") or
		androguard.certificate.sha1("60DDC46BD8ADC74137C5EF39F65C1C8497CB9809")
		
}