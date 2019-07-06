import "androguard"


rule whatsdog : test
{
	meta:
		description = "Fake Whatsdog apps"

	condition:		
		androguard.app_name("WhatsDog") and 
		not androguard.certificate.sha1("006DA2B35407A5A017F04C4C675B05D3E77808C9")
		
}