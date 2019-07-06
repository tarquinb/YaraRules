import "androguard"


rule Malicious_certificate
{
	meta:
		description = "This rule detects Mazarbot samples for Raiffeisen bank"
		samples = "5c5f7f9e07b1e1c67a55ce56a78f717d"

	condition:
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB")
		
}