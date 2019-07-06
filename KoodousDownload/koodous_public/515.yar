import "androguard"

rule Installer: banker
{
	meta:
		description = "Applications with Installer as an application name"

	condition:
		androguard.package_name("Jk7H.PwcD")
}