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
	"github.com/SSSaaS/sssa-golang"
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

	shares := make([]string, numShares)

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
		shares[i] = string(share)
	}
	privkey, _ := sssa.Combine(shares)
	privKeyBytes := []byte(privkey)
	fmt.Printf("Private key: \t%s\n", hex.EncodeToString(privKeyBytes))
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
	privkey = make ([]byte, 88)
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
