// source: https://garbagecollected.org/2014/09/14/how-google-authenticator-works/

package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"os"
)

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint64(bytes []byte) uint64 {
	return (uint64(bytes[0]) << 24) + (uint64(bytes[1]) << 16) +
		(uint64(bytes[2]) << 8) + uint64(bytes[3])
}

func oneTimePassword(key []byte, value []byte) uint64 {
	// sign the value using HMAC-SHA512
	hmacSha512 := hmac.New(sha512.New, key)
	hmacSha512.Write(value)
	hash := hmacSha512.Sum(nil)

	// using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint64(hashParts)

	// size to 10 digits
	pwd := number % 10000000000

	return pwd
}

// all []byte in this program are treated as Big Endian
func main() {

	// ninja@example.comHDECHALLENGE003
	input := "NZUW42TBIBSXQYLNOBWGKLTDN5WUQRCFINEECTCMIVHEORJQGAZQ===="
	key, err := base32.StdEncoding.DecodeString(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// generate a one-time password using the time at 30-second intervals
	epochSeconds := int64(1395069651) // time.Now().Unix()
	pwd := oneTimePassword(key, toBytes(epochSeconds/30))

	secondsRemaining := 30 - (epochSeconds % 30)
	fmt.Printf("%06d (%d second(s) remaining)\n", pwd, secondsRemaining)
}

// Output : 1264436375
