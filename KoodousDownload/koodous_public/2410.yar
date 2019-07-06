import "androguard"
import "droidbox"


rule Dropper : OmniRAT Dropper
{
	meta:
        description = "Dropper for OmniRAT"
		

	condition:
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) 
		and androguard.activity(/net.filsh.youtubeconverter.MainActivity/)
}