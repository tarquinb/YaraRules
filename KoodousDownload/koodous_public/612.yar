//Updated V2 version

rule MobiDash
{
	meta:
		description = "MobiDash Adware evidences"

	strings:
		$a = "mobi_dash_admin" wide ascii
		$b = "mobi_dash_account_preferences.xml" wide ascii

	condition:
		all of them
}

rule MobiDash_v3
{
	meta:
		description = "MobiDash Adware evidences v3"
		sample = "6c2ffbede971283c7ce954ecf0af2c5ea5a5d028d3d013d37c36de06e9e972f3"

	strings:
		$1 = "Lmobi/dash/api/BannerRequest" wide ascii
		$2 = "mobi.dash.sdk.AdmobActivity" wide ascii

	condition:
		1 of them
}