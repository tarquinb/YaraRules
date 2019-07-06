import "androguard"

rule MilkyDoor {
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/operation-c-major-actors-also-used-android-blackberry-mobile-spyware-targets/"
	
	strings:
	  	$ = /144.76.108.61/
		$ = /hgnhpmcpdrjydxk.com/
		$ = /jycbanuamfpezxw.com/
		$ = /liketolife.com/
		$ = /milkyapps.net/
		$ = /soaxfqxgronkhhs.com/
		$ = /uufzvewbnconiyi.com/
		$ = /zywepgogksilfmc.com/

	condition:
		1 of them

}