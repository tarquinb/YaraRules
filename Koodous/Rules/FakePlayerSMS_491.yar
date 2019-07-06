import "androguard"

rule FakePlayerSMS
{
	condition:
		androguard.app_name(/PornoPlayer/) and
		androguard.permission(/SEND_SMS/)		
}