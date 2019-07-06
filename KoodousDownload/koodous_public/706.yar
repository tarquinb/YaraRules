import "androguard"


rule smsfraud
{
	meta:
		description = "This rule detects apks related with sms fraud"
		sample = "79b35a99f16de6912d6193f06361ac8bb75ea3a067f3dbc1df055418824f813c"

	condition:
		androguard.certificate.sha1("1B70B4850F862ED0D5D495EC70CA133A4598C007")
		
}