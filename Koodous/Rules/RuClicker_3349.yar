import "androguard"
import "file"
import "cuckoo"


rule RuClicker
{
	strings:
		$ = "CiLscoffBa"
		$ = "FhLpinkJs"
		$ = "ZhGsharecropperFx"

	condition:
 		all of them
}