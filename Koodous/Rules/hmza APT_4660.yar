import "androguard"

rule APT_hmza
{
	meta:
		description = "This rule will be able to tag all hmza APT samples"
		hash_1 = "2d0a56a347779ffdc3250deadda50008d6fae9b080c20892714348f8a44fca4b"
		hash_2 = "caf0f58ebe2fa540942edac641d34bbc8983ee924fd6a60f42642574bbcd3987"
		hash_3 = "b15b5a1a120302f32c40c7c7532581ee932859fdfb5f1b3018de679646b8c972"
		author = "Jacob Soo Lead Re"
		date = "16-July-2018"
	condition:
		androguard.service(/NetService/i)
		and androguard.receiver(/hmzaSurvival/i) 
		and androguard.receiver(/SystemUpteen/i)
}