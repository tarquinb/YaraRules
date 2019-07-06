import "androguard"

rule Gen_AIDE
{
	meta:
		description = "Rule to detect malware variant (ex:Jisut)"
		ref = "https://www.welivesecurity.com/wp-content/uploads/2016/02/Rise_of_Android_Ransomware.pdf"
		
		condition:
		 androguard.service("cn.sadsxcds.sadcccc.SmSserver") or
		 androguard.activity("com.dq.raw.MainActivity") or
		 androguard.activity("com.magic.ten.mad.MainActivity") or
         androguard.receiver("com.h.MyAdmin") or
		 androguard.receiver("com.h.bbb") or
		 androguard.receiver("com.sssp.bbb") or
		 androguard.receiver("com.sssp.MyAdmin") or
		 androguard.receiver("com.cjk.bbb") or
		 androguard.receiver("com.cjk.MyAdmin") or
		 androguard.receiver("com.cute.pin.Pin") or
		 androguard.receiver("com.sunglab.bigbanghd.Service")
}