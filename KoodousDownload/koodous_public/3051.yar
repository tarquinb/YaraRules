import "androguard"
import "cuckoo"

rule SmsFraudUsingURLsAndDNS : smsfraud
{
	meta:
		description = "This rule should match applications that send SMS"
		inspired_by = "https://koodous.com/rulesets/3047"

	condition:
		androguard.url("app.tbjyz.com")
		or androguard.url("tools.zhxapp.com")
		or cuckoo.network.dns_lookup(/app\.tbjyz\.com/)
		or cuckoo.network.dns_lookup(/tools\.zhxapp\.com/)
}