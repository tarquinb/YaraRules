import "androguard"



rule apkfiles : official
{
	meta:
		description = "Accede a un repositorio de apks"

	condition:
		androguard.url(/www\.apkfiles\.com/)
}