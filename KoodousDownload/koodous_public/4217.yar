import "androguard"

rule Title_Santander {

	strings:
		$string_1 = /Santander/
		$string_2 = /Spendlytics/
		$string_3 = /SmartBank/
		$string_4 = /Flite/
		
	condition:
	1 of ($string_*)
}

rule Androguard_Santander {
	meta:
		description = "Per Package detection"
	condition:
		androguard.package_name("es.bancosantander.accionistas.uk") or
		androguard.package_name("com.osper.santander") or
		androguard.package_name("uk.co.santander.smartbank") or
		androguard.package_name("uk.co.santander.flite") or
		androguard.package_name("com.santander.kitti") or
		androguard.package_name("uk.co.santander.isasUK") or
		androguard.package_name("uk.co.santander.santanderUK") or
		androguard.package_name("uk.co.santander.businessUK.bb") or
		androguard.package_name("uk.co.santander.spendlytics")
}