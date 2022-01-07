rule mncmccLeakage
{
        meta:
                author = ""
                description = "pattern matching on mnc or mcc in pcaps (Dev Rule)"
                version = "0.1"
                known_fp = ""

        strings:
                $re1 = /\bmnc=\d{2,3}\b/ nocase
                $re2 = /\bmcc=\d{1,3}\b/ nocase
                $re3 = /\bmncmcc\b/ nocase
                $re4 = /\bcsc=\w{1,4}\b/

        condition:
                any of them

}
