# Yara Parameters

```bash
yara.exe test.yar -r (recursive) -s (show matching string $s1)
```

# Yara Strings

```bash
$hex_string = { EB FE [2-4] ?? (13 37 | 73 31) }
/*
? wild card
[2-4] arbitrary bytes
(x | y) = (x or y)
*/

$fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
```

```bash
$reg_ex = /md5: [0-9a-zA-Z]{32}/
		/*
		string modifiers nocase, wide, ascii, and fullword can be used
		\ Quote the next metacharacter
		^ Match the beginning of the file
		$ Match the end of the file
		| Alternation
		() Grouping
		[] Bracketed character class
		* Match 0 or more times
		+ Match 1 or more times
		? Match 0 or 1 times
		{n} Match exactly n times
		{n,} Match at least n times
		{,m} Match 0 to m times
		{n,m} Match n to m times
		*? Match 0 or more times, non-greedy
		+? Match 1 or more times, non-greedy
		?? Match 0 or 1 timetimes, non-greedy
		{n}? Match exactly n times, non-greedy
		{n,}? Match at least n times, non-greedy
		{,m}? Match 0 to m times, non-greedy
		{n,m}? Match n to m times, non-greedy
		\t Tab (HT, TAB)
		\n New line (LF, NL)
		\r Return (CR)
		\f Form feed (FF)
		\a Alarm bell (BEL)
		\x00 Character whose ordinal number is the given
		hexadecimal number
		\w Match a “word” character (aphanumeric plus “_”)
		\W Match a non-“word” character
		\s Match a whitespace character
		\S Match a non-whitespace character
		\d Match a decimal digit character
		\D Match a non-digit character
		*/
```



# Yara Conditions

````bash
$txt_string or ($hex_string and $reg_ex) 
all of them // all strings in the rule
any of them // any string in the rule
all of ($a*) //all strings whose identifier starts by $a
any of ($a,$b,$c) // any of $a, $b or $c
1 of ($b*) // same that "any of them"
3 of them // matches any x of the strings


// Useful conditions to check if file is a PE
uint16(0) == 0x5A4D and // MZ signature at offset 0 and 
uint32(uint32(0x3C)) == 0x00004550 // PE signature at offset stored in MZ header at 0x3C!

include "./includes/other.yar"! // include other rule files
````





