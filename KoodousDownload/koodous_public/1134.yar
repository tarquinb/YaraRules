rule fakeInstaller
{
	meta:
		description = "This rule detects application that simulate an Installer"
		sample = "e8976d91cbfaad96f9b7f2fd13f2e13ae2507e6f8949e26cbd12d51d7bde6305"

	strings:
		$a = "res/raw/animation.txtPK"
		$b = "res/raw/roolurl.txtPK"
		$c = "cpard/ivellpap"
		$d = "http://wap4mobi.ru/rools.html"
		$e = "res/raw/conf.txtPK"

	condition:
		all of them
}

rule fakeinstaller_sms
{
	strings:
		$a = "http://sms24.me" wide
		$b = "http://sms911.ru" wide
		$c = "smsdostup.ru" wide
	condition:
		any of them
}