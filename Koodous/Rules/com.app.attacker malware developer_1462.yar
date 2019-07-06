import "androguard"


rule koodous : official
{
	meta:
        description = "Rule to catch APKs with package name match with com.app.attacker."
    condition:
        androguard.package_name(/com\.app\.attacker\../)
		
}