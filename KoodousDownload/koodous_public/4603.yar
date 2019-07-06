import "androguard"
import "file"
import "cuckoo"


rule whatsapp : meterpreter
{
	meta:
		description = "This rule detects the Whatsapp infected with a payload"


	condition:
		androguard.package_name("com.whatsapp") and
		androguard.app_name("WhatsApp") and
		androguard.certificate.sha1("FBA7AC627447E3E79A5F084EE750A250B286B1F8")
}