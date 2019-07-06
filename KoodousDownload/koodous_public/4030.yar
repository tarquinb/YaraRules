import "androguard"

rule redalert2

{
	meta:
		description = "RedAlert2.0"
		family = "Red Alert"


	condition:
	
		(androguard.url(/:7878/) or androguard.url(/:6280/)) or
		(androguard.service("westr.USSDService") and androguard.service("westr.service_rvetdi5xh.MessageBltService_df3jhtrgft43") and  androguard.service("westr.service_rvetdi5xh.WldService_dfgvgfd") and
		androguard.service("westr.service_rvetdi5xh.McdxService_efv3web")) or androguard.url("https://ttwitter.com/")


			
}