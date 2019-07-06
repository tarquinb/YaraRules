
rule unknown

{

    meta:

        //description = "This rule detects the koodous application, used to show all Yara rules potential"

        sample = "ee05cbd6f7862f247253aa1efdf8de27c32f7a9fc2624c8e82cbfd2aab0e9438"

        search = "package_name:com.anrd.bo"


    strings:

        $a = "543b9536fd98c507670030b9" wide

        $b = "Name: assets/su"


    condition:

        all of them

}