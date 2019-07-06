import "androguard"

rule groups : authors2
{
	meta:
		description = "To find groups of apps with old testing certificate, signapk tool used it. Recently apps should not have this certificate"
		

	condition:
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81")

		
}