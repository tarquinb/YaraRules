import "androguard"

rule koodous : official
{
	meta:
		description = "This rule detects apks fom ASSD developer"
		sample = "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e"

	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
		
}