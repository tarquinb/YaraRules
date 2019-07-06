rule sample_banker : banker
{
meta: 
description = "sample rule to detect the malware sample"
thread_level = 2

strings:
$a = "aaAmerican Express The CVC is the four digits located on the front of the card,"
$b = "Keep your Internet Banking and secret authorisation code (SMS) secret."
$c = "XPhone number had an IDD, but after this was not long enough to be a viable phon"

condition:
$a and $b and $c
}