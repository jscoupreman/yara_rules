rule Find_Das_Good_Restaurant
{
	meta:
		author = "The damn good restaurant seeker"
		date = "10/10/2020"
		description = "This rule finds the best damn good restaurant in the area."
		
	strings:
		$cooking_type1 = "chinese"
		$cooking_type2 = "japanese"
		$cooking_type3 = "greek"
		$cooking_type4 = "italian"
		$noodles = "das gud chinese chef noodles"
		$pizza_prep = "wood-fired pizza"
		
	condition:
		($cooking_type1 and $noodles) or $cooking_type2 or $cooking_type3 or ($cooking_type4 and $pizza_prep)
}