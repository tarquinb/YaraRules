import "androguard"

rule APT_Loader
{
	meta:
		description = "This rule will be able to tag this particular loader samples"
		hash_1 = "8f062f35fd838b00b6cfc3e7df3adedfe710e5f205f48e280e75a885d474b29b"
		Reference = "https://twitter.com/ThreatFabric/status/1020619670565597184"
		author = "Jacob Soo Lead Re"
		date = "16-July-2018"
	condition:
		androguard.activity(/AdminActivity/) and
		androguard.activity(/MainActivity/) and
		androguard.service(/AdminService/) and
		androguard.service(/MainService/) and
		androguard.receiver(/AdminReceiver/) and
		androguard.receiver(/MainReceiver/)
}