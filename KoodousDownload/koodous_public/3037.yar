import "androguard"



rule khashayar_talebi
{
	meta:
		description = "Possible Threats, Domains registered for khashayar.talebi@yahoo.com"


	strings:
		$ = "tmbi.ir"
		$ = "masirejavan.ir"
		$ = "clipmobile.ir"
		$ = "razmsport.ir"
		$ = "norehedayat.ir"
		$ = "dlappdev.ir"
		$ = "telememberapp.ir"
		$ = "btl.ir"
		$ = "niazeparsi.ir"
		$ = "imdbfa.ir"
		$ = "thecars.ir"
		$ = "rahaserver.ir"
		$ = "mehrayen.ir"

	condition:
		1 of them
		
}