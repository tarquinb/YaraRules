
rule SMSReg

{

    meta:

        description = "This rule detects SMSReg trojan"

        sample = "b9fd81ecf129d4d9770868d7a075ba3351dca784f9df8a41139014654b62751e"


    strings:

        $a = "before send msg to cu server optaddr"

        $b = "Service destory"

        $c = "Enter start service"

        $d = "The sim card in this phone is not registered, need register"


    condition:

        all of them


}