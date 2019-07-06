import "androguard"


rule marcher_v2
{
	meta:
		description = "Detect marcher based on activity, service, receiver names."
		sample = "d7ff6de3f8af4af7c740943af3aaaf631a8baec42090f902bd7517e0190a1a21"

	condition:
		androguard.activity(/\.p0[0-9]{2}[a-z]\b/) and
		androguard.service(/\.p0[0-9]{2}[a-z]\b/) and
		androguard.receiver(/\.p0[0-9]{2}[a-z]\b/)
}