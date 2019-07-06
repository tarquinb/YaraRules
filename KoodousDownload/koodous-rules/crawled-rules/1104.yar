
rule smsreg

{

    meta:

        description = "SMSReg"

        sample = "f861d78cc7a0bb10f4a35268003f8e0af810a888c31483d8896dfd324e7adc39"


    strings:

        $a = {F0 62 98 9E C7 52 A6 26 92 AB C1 31 63}


    condition:

        all of them

}