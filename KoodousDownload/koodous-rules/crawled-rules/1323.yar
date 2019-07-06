
rule adware

{

    meta:

        //description = "This rule detects the koodous application, used to show all Yara rules potential"

        sample = "28e2d0f5e6dca1b108bbdc82d8f80cfbf9acd1df2e89f7688a98806dc01a89ba"

        search = "package_name:com.blackbean.cnmeach"


    strings:

        $a = "CREATE TABLE IF NOT EXISTS loovee_molove_my_date_history"

        $b = "loovee_molove_my_dating_task_delete_bak"


    condition:

        all of them


}