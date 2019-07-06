import "androguard"

rule HiddenApp {
	
	strings:
	  	$ = /ssd3000.top/
		$ = "com.app.htmljavajets.ABKYkDEkBd"

	condition:
		1 of them

}