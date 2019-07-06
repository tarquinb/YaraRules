import "androguard"


rule koodous : UC_Safe 
{

	condition:
		androguard.package_name("com.uc.iflow") and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139")  
}