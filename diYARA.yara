rule pcapMagByt
{
        meta:
                author = "Genevieve Bronson"
                date = "18-10-2022"
                description = "checks the magic bytes of pcap files"
        strings:
                $magic = {D4 C3 B2 A1}
        condition:
                $magic at 0
}

rule jpgMagByte
{
meta:
author = "Genevieve"
description = "checks for magic bytes in jpgs"
        strings:
                $magic = {FF D8 FF E0}
        condition:
                $magic at 0
}

rule NotTheDroid
{
meta:
author = "gen"
description = "looks for the string or base64 of the statement and ignores case"
strings:
$a = "This is not the droid youre looking for" nocase
$b = "this is not the droid youre looking for" base64
condition:
$a or $b
}

rule containsAll
{
meta:
author = " genevieve"
description = "checks if and b or a and c are true"
strings:
$a = "apple"
$b = "banana"
$c = "orange"
condition:
$a and $b or $a and $c
}

rule sandwich
{
    meta:
    author = "genevieve"
    description = "looks for the hex of the words lettuce and tomato"
strings:
$a = {74 6f 6d 61 74 6f}
$b = {6c 65 74 74 75 63 65}
condition:
$a and $b
}

rule lyric
{
    meta:
    author = "genevieve"
    description = "looks for the hex of the words movie and friend"
strings:
$a = {66 72 69 65 6e 64}
$b = {6d 6f 76 69 65}
condition:
$a and $b
}
