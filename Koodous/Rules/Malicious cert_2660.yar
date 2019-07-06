import "androguard"

rule malicious_cert
{
	meta:
		description = "This rule detects apps with malicious certs"
		sample = "a316a8cccbee940c3f0003344e6e29db163b1c82cd688bdc255a69300470124c"

	condition:
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB")
		
}