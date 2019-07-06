import "androguard"
//android.permission.SEND_SMS


rule fakeav_cert 
{
	meta:
		description = "fakeav msg premium"
		sample = ""


	condition:
		androguard.certificate.sha1("1C414E5C054136863B5C460F99869B5B21D528FC")
		
}

rule fakeav_url
{
	meta:
		description = "fakeav msg premium"
		sample = ""


	condition:
		androguard.url(/topfiless\.com\/rates\.php/) 
		
}