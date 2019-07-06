
rule basebridge

{

    meta:

        description = "A forwards confidential details to a remote server."

        sample = "7468c48d980f0255630d205728e435e299613038b53c3f3e2e4da264ceaddaf5"

        source = "https://www.f-secure.com/v-descs/trojan_android_basebridge.shtml"


    strings:

        $a = "zhangling1"


    condition:

        all of them


}