rule androidPackageNames
{
        meta:
                author = "@MamrK29"
                description = "Detect android application package names"
                version = "0.2"
                missing_detections = "Only triggers on TLD .com and .org"
        false_postives = "picks up actual domains as well"

        strings:
                $capComTLD = /\b([a-zA-Z]+)?\.?com\.[A-Za-z0-9\_]+\.[A-Za-z0-9\_]+\b/
                $capOrgTLD = /\b([a-zA-Z]+)?\.?org\.[A-Za-z0-9\_]+\.[A-Za-z0-9\_]+\b/

        condition:
        any of them
}
