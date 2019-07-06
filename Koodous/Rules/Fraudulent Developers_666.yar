import "androguard"

rule fraudulent_developers : airpush
{
	condition:
		androguard.certificate.issuer(/tegyhman/) 
		or androguard.certificate.issuer(/tengyhman/)
		or androguard.certificate.issuer(/pitorroman/) 
		or androguard.certificate.subject(/pitorroman/)
}