import "androguard"
import "cuckoo"

rule AndroidAdServer
{
	meta:
		description = "Rule to catch APKs speaking to a noisy ad server"
	condition:
		androguard.url(/123\.56\.205\.151/) or
		androguard.url("123.56.205.151") or
		cuckoo.network.dns_lookup(/123\.56\.205\.151/)

}