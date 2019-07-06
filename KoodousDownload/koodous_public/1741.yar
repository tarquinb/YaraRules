import "androguard"

rule Android_Aulrin
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-August-2016"
		description = "This rule try to detect Aulrin. This"
	condition:
		androguard.receiver(/z.core.OnBootHandler/i) and
		androguard.receiver(/z.core.SMSReciever/i) and
		androguard.service(/z.core.RunService/i) and
		androguard.activity(/xamarin.media.MediaPickerActivity/i) and 
        androguard.permission(/android.permission.CHANGE_COMPONENT_ENABLED_STATE/i)
}