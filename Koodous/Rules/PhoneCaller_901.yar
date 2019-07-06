import "droidbox"

rule PhoneCall
{
	meta:
		description = "Phone Caller"
		
	condition:
		droidbox.phonecall(/./)
}