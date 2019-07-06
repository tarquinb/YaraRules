import "androguard"


rule FakeAppCampaign1
{
	meta:
		description = "This rule detects fake application with only the payment gateway delivering no service"
		sample = "c30d57bc5363456a9d3c61f8e2d44643c3007dcf35cb95e87ad36d9ef47258b4"

	strings:
		$url1 = /https:\/\/telehamkar.com\//
		$url2 = /weezweez.ir/

	condition:
		$url1 or $url2
		
}