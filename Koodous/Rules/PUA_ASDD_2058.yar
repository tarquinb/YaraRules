import "androguard"



rule PUA : ASDD
{
	

	condition:
		androguard.certificate.sha1("ed9a1ce1f18a1097dccc5c0cb005e3861da9c34a") 
		
}