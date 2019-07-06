import "androguard"



private global rule samsung_Safe
{
	condition:
		androguard.certificate.sha1("9ca5170f381919dfe0446fcdab18b19a143b3163")
}