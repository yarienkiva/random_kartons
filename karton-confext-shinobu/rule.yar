rule shinobu {
	meta:
		description = "This rule detects the clipper bundled with leaked software"
		author = "yarienkiva"
		date = "2023-02-16"
		reference = "https://heartathack.club/blog/analyzing-a-generic-clipper"

	strings:
		// suspicious strings
		$m1 = ".NET Framework"             ascii fullword
		$m2 = "AddClipboardFormatListener" ascii fullword
		$m3 = "ClipboardNotification"      ascii fullword

		// config
		$c1 = "ethereum"  ascii fullword
		$c2 = "xmr"       ascii fullword
		$c3 = "btc"       ascii fullword

		$c4 = "Mutexx"    ascii fullword
		$c5 = "startup"   ascii fullword
		$c6 = "url"       ascii fullword

		$c7 = "ethereumE" ascii fullword
		$c8 = "xmrE"      ascii fullword
		$c9 = "btcE"      ascii fullword

	condition:
		uint16(0) == 0x5a4d and
		filesize < 200KB and
		all of them
}
