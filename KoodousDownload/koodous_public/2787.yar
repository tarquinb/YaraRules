rule Regla_Deutsche_Finanz_Malware

{
	
meta:
    description = "Regla Yara para detectar malware del Deutsche Bank Finanz"
    sample = "83a360f7c6697eda7607941f769050779da1345a0dde015b049109bc43fc3a3e"

strings:
 	$a = "#intercept_sms_start"
	$b = "#intercept_sms_stop"
	$c = "org/slempo/service/DialogsStarter"



condition:
	$a and $b and $c
}