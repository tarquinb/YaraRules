import androguard
        rule adware {
            condition:
				androguard.filter("com.airpush.android.DeliveryReceiver") or
				androguard.filter(/smsreceiver/)
				androguard.filter()
        }