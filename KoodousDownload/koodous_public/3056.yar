import "androguard"
import "file"

rule APITesting : NotNecessaryMalware
{
	meta:
		description = "This rule was created just to test extensively the androguard API"
		disclaimer = "does not match necessary any kind of malware, it was created randomly"

	condition:
		file.size > 512KB
		and androguard.number_of_permissions >= 20
		and androguard.number_of_filters <= 100
		and androguard.number_of_activities > 30
		and (
			androguard.number_of_providers > 1
			or androguard.number_of_services > 1
		)
}