
rule loki_skd

{

    meta:

    description = "This rule detects com.loki.sdk"


    strings:

        $a = "com/loki/sdk/"

        $b = "com.loki.sdk.ClientService"


    condition:

        $a or $b


}