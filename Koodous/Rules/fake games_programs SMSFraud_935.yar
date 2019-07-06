import "androguard"

rule koodous : official
{
	meta:
		description = "This ruleset detects a family of smsfraud trojans"
		sample = "110f2bd7ff61cd386993c28977c19ac5c0b565baec57272c99c4cad6c4fc7dd4"

	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.certificate.sha1("4B01DF162934A8E6CF0651CE4810C83BF715A55D") 
}