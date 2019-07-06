import "androguard"

rule hao
{
	meta:
		description = "Developer / Company: hao"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		search = "cert:7428EA9322A6FBF2DDE4A6DB6C6E59237E0D8EC3" 

	condition:
		androguard.certificate.sha1("7428EA9322A6FBF2DDE4A6DB6C6E59237E0D8EC3")
}