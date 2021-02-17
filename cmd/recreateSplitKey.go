/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"strconv"
	"github.com/san-lab/secretsplitcli/goethkey"
	"github.com/spf13/cobra"
	"strings"
)

// readKeyfileCmd represents the readKeyfile command
var recreateSplitKeyCmd = &cobra.Command{
	Use:   "reacreateSplitKey",
	Short: "Read an Ethereum key file",
	Long:  `A longer description will follow soon.`,
	Run:   reacreateSplitKey,
}

func reacreateSplitKey(cmd *cobra.Command, args []string) {
	var numShares int
	fmt.Print("Enter the number of shares to be used: ")
	fmt.Scanf("%d", &numShares)
	fmt.Print("\n")

	var arrayShareBytes [][]byte

	for i := 0; i < numShares ; i++ {
		var filename string
		fmt.Print("Enter the name of share " + strconv.Itoa(i+1) + ": ")
		fmt.Scanf("%s", &filename)

		keyfile, err := goethkey.ReadKeyfile(filename)
		if err != nil { fmt.Println(err); return}

		//TODO Handle the unencrypted kyefiles

		//derive the key from password
		var key []byte
		switch keyfile.Crypto.Kdf {
		case "scrypt":
			var macok bool
			key, macok = handleScrypt(keyfile)
			if !macok {return}

		default:
			fmt.Println("Unsupported KDF: ", keyfile.Crypto.Kdf)
			return
		}
		share, errDec := decryptAndReturn(keyfile, key)
		if errDec != nil { fmt.Println(errDec); return}
		arrayShareBytes = append(arrayShareBytes, share)
	}

	var sharesOut []*share.PriShare
	for i, b := range arrayShareBytes {
		fmt.Println(i)
		s2 := new(sharePrishare)
		e := s2.UnmarshalJSON(b)
		fmt.Println(e, "JSON post", *s2)
		sharesOut = append(sharesOut, &share.PriShare{s2.I, s2.V})
	}

	fmt.Println("JSON", sharesOut)

	rec, _ := share.RecoverSecret(pairing.NewSuiteBn256().G1(), sharesOut, minShares, minShares)
	b, _ := rec.MarshalBinary()
	retrievedKey := hex.EncodeToString(b)
	fmt.Printf("Private key: \t%s\n", retrievedKey)
}

//This assumes that the MAC verification has been OK
func decryptAndReturn (kf *goethkey.Keyfile, key []byte) (privkey []byte, err error) {
	switch strings.ToLower(kf.Crypto.Cipher) {
	case "aes-128-ctr":
		privkey, err = decryptAES128CTRBig(kf,key)
	default:
		err = fmt.Errorf("Not implemented cipher: %s\n", kf.Crypto.Cipher)
		return
	}

	return privkey, nil
}

func decryptAES128CTRBig(kf *goethkey.Keyfile, key []byte) (privkey []byte, err error) {
	block, err := aes.NewCipher(key[0:16])
	if err != nil { return}
	iv, err := hex.DecodeString(kf.Crypto.Cipherparams.Iv)
	if err != nil { return}
	stream := cipher.NewCTR(block, iv)
	citx, err := hex.DecodeString(kf.Crypto.Ciphertext)
	if err != nil {  return}
	privkey = make ([]byte, 68)
	stream.XORKeyStream(privkey,citx)
	return

}

func init() {
	rootCmd.AddCommand(recreateSplitKeyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// readKeyfileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// readKeyfileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

//func fromBase64(number string) *big.Int {
//	bytedata, err := base64.URLEncoding.DecodeString(number)
//	if err != nil {
//		return big.NewInt(-1)
//	}
//
//	hexdata := hex.EncodeToString(bytedata)
//	result, ok := big.NewInt(0).SetString(hexdata, 16)
//	if ok == false {
//		return big.NewInt(-1)
//	}
//
//	return result
//}

/**
 * Converts an array of big.Ints to the original byte array, removing any
 * least significant nulls
**/
//func mergeIntToByte(secret []*big.Int) []byte {
//	var hex_data = ""
//	for i := range secret {
//		tmp := fmt.Sprintf("%x", secret[i])
//		hex_data += strings.Join([]string{strings.Repeat("0", (64 - len(tmp))), tmp}, "")
//	}
//
//	result, _ := hex.DecodeString(hex_data)
//	result = bytes.TrimRight(result, "\x00")
//
//	return result
//}
//
//func modInverse(number *big.Int) *big.Int {
//	copy := big.NewInt(0).Set(number)
//	copy = copy.Mod(copy, defaultPrime)
//	pcopy := big.NewInt(0).Set(defaultPrime)
//	x := big.NewInt(0)
//	y := big.NewInt(0)
//
//	copy.GCD(x, y, pcopy, copy)
//
//	result := big.NewInt(0).Set(defaultPrime)
//
//	result = result.Add(result, y)
//	result = result.Mod(result, defaultPrime)
//	return result
//}

//func recreate(x []*big.Int, y []*big.Int) {
//	zero := big.NewInt(0)
//	totSum := big.NewInt(0)
//	summand := big.NewInt(0)
//	for i := 0; i < len(x); i++ {
//		numerator := big.NewInt(1)
//		denominator := big.NewInt(1)
//		for j := 0; j < len(x); j++{
//			if j != i {
//				negative := big.NewInt(0)
//				negative.Sub(zero, x[j])
//				numerator.Mul(numerator, negative)
//				numerator.Mod(numerator, defaultPrime)
//
//				denominator = big.NewInt(0)
//				denominator.Sub(x[i], x[j])
//				denominator.Mod(denominator, defaultPrime)
//			}
//		}
//		summand = big.NewInt(0).Set(y[i])
//		summand.Mul(summand,numerator)
//		summand.Mul(summand, modInverse(denominator))
//
//		totSum.Add(totSum, summand)
//		totSum.Mod(totSum, defaultPrime)
//	}
//	var totSumArr []*big.Int
//	totSumArr = append(totSumArr,totSum)
//	resultEnd := string(mergeIntToByte(totSumArr))
//	resultEndBytes := []byte(resultEnd)
//	fmt.Printf("Private key: \t%s\n", hex.EncodeToString(resultEndBytes))
//}
