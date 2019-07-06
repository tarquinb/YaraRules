import "androguard"


rule Hiv13PhishingCampaign
{
	meta:
		description = "This campaign shows phishing payment page and gathers users card information"
		sample = "4750fcaf255107a8ee42b6a65c3ad6c609ef55601a94f2b6697e86f31cff988c"

	strings:
		$a = /hiv13.com/

	condition:
		$a
}