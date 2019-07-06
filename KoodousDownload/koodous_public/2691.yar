import "androguard"


rule badaccents
{
	meta:
		description = "This rule detects badaccents"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"



	condition:
		androguard.activity(/Badaccents/i) 
	
		
}