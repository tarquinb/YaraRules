import "androguard"


rule Lockerpin2 : ransomware
{
	meta:
		description = "Lockerpin"
		sample = "ca6ec46ee9435a4745fd3a03267f051dc64540dd348f127bb33e9675dadd3d52"

	strings:
		$alert_text = "All your contacts <b>are copied</b>. If you do not pay the fine, we will <b>notify</b> your <u>relatives</u> and <u>colleagues</u> about <b>the investigation</b>"

	condition:
		(androguard.permission(/android\.permission\.READ_CONTACTST/) or
		androguard.permission(/android\.permission\.DISABLE_KEYGUARD/) or
		androguard.permission(/android\.permission\.WRITE_SETTINGS/)) and
		$alert_text	
}

rule lockerpin
{
	meta:
		author = "asanchez"
		description = "This rule detects LockerPin apps"
		sample = "2440497f69ec5978b03ea5eaf53a63f5218439a6e85675811c990aa7104d6f72"
		sample2 = "99366d0bd705e411098fade5a221a70863038f61344a9f75f823c305aa165fb1"
		sample3 = "ca6ec46ee9435a4745fd3a03267f051dc64540dd348f127bb33e9675dadd3d52"

	strings:
		$a = "res/drawable-hdpi-v4/fbi.png"
		$b = "<b>IMEI:</b>"
		$c = "res/drawable-xhdpi-v4/hitler_inactive.png"
		$d = "res/drawable-xhdpi-v4/gov_active.pngPK"

	condition:
		all of them
		
}