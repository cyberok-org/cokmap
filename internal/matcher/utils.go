package matcher

import "strconv"

func hexStringToRunes(hexString string) ([]rune, error) {
	// capacity of the slice is half the length of the hex string because each unicode point is represented by two hex chars
	runes := make([]rune, 0, len(hexString)/2)
	// iterate over the hex string by pairs of characters
	for i := 0; i < len(hexString); i += 2 {
		// extract a pair of characters from the hex string
		hexCode := hexString[i : i+2]
		// convert the pair of characters to a base-16 unsigned integer aka code point using ParseUint
		codePoint, err := strconv.ParseUint(hexCode, 16, 32)
		if err != nil {
			return nil, err
		}
		runes = append(runes, rune(codePoint))
	}
	return runes, nil
}
