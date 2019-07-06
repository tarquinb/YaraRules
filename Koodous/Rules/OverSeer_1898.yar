import "androguard"

rule Android_OverSeer
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-August-2016"
		description = "This rule try to detect OverSeer."
		references = "https://blog.lookout.com/embassy-spyware-google-play"
	condition:
		androguard.receiver(/test\.parse\.AlarmReceiver/i) and
		androguard.receiver(/test\.parse\.SenderReceiver/i) and
		androguard.receiver(/test\.parse\.NetworkReceiver/i) and
		androguard.filter(/dex\.SEND_ACTION/i)
}