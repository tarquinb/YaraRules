
rule binka

{

    meta:

        description = "Binka banker trojan"

        sample = "4b2955436dacdc9427635794ff60465bc9bd69d31629e3337e012bd32e964e57"


    strings:

        $a = "EditText01"

        $b = "vel (exemplo: 960000111 e criar a palavra chave)"

        $c = "userText"

        $d = "LinearLayout04"

        $e = "TextView01"

        $f = "a de TMN tem de introduzir o n"

        $g = "LinearLayout03"

        $h = "LinearLayout02"

        $i = "LinearLayout01"

        $j = "LayoutOk"

        $k = "Para gerar o certificado de segura"

        $l = "startForService"

        $m = "Context is null"



    condition:

        all of them

}