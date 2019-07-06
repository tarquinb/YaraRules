import "androguard"
import "cuckoo"

rule clicker : url
{
	meta:
		description = "This rule detects the Fake installer malwares by using visited URL"
		sample = "aa560b913446d45d29c5c0161bbe6e4c16f356afd818af412c56cde0ae5a6611"
	
	condition:
		cuckoo.network.http_request(/^http?:\/\/suitepremiumds\.ru/) or 
		cuckoo.network.http_request(/suitepremiumds\.ru/) or 
		androguard.url(/^http?:\/\/suitepremiumds\.ru/) or 
		androguard.url(/suitepremiumds\.ru/)
		
}