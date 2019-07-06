import "androguard"
import "file"
import "cuckoo"

rule kevdroid
{
	meta:
		description = "This rule detects suspicious KevDroid certificate"
		sample1 = "f33aedfe5ebc918f5489e1f8a9fe19b160f112726e7ac2687e429695723bca6a"
		sample2 = "c015292aab1d41acd0674c98cd8e91379c1a645c31da24f8d017722d9b942235"
		author = "DMA"


	condition:
	//"issuerDN": "/C=US/ST=US/L=Washington/O=kevin/OU=kevin/CN=kevin",
		androguard.certificate.sha1("A638D0C9CC18AC0E5D2EC83144EA237DFFA1FA2A")
		
}