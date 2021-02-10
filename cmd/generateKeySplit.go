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
	"github.com/spf13/cobra"
	"time"
	"github.com/san-lab/secretsplitcli/goethkey"
	"github.com/SSSaaS/sssa-golang"
	"fmt"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"github.com/btcsuite/btcd/btcec"
	"github.com/google/uuid"
	"encoding/json"
	"io/ioutil"
	"strconv"
)

// generateKeyfileCmd represents the generateKeyfile command
var generateKeySplitCmd = &cobra.Command{
	Use:   "generateKeySplit totalShares MinShares baseFilename",
	Short: "Generates shamir secret shares of a private key",
	Long: `Generates shamir secret shares of a private key. Interactively asks for passwords (do not forget your choice!).`,
	Run: generateKeySplit,
}

var numShares, minShares int
var genFilenameBase string
var kdfNew string
var ethkeyStr string

func generateKeySplit(cmd *cobra.Command, args []string) {
	numShares64,_ := strconv.ParseInt(args[0], 10, 64)
	minShares64,_ := strconv.ParseInt(args[1], 10, 64)

	numShares = int(numShares64)
	minShares = int(minShares64)

	if len(args) == 3 {
		genFilenameBase = args[2]
	} else {
		genFilenameBase = time.Now().Format(time.RFC3339) + ".json"
	}

	//for len(pass) <

	//Generate the Koblitz private key
	ethkey := make([]byte, 32)
	rand.Read(ethkey)
	fmt.Printf("Private key: \t%s\n", hex.EncodeToString(ethkey))
	ethkeyStr = string(ethkey)

	shares, errShares := sssa.Create(minShares, numShares, ethkeyStr)
	if errShares != nil {fmt.Println(errShares); return}

	for i:= 0; i < len(shares); i++ {
		shareBytes := []byte(shares[i])
		fmt.Printf("Size: \t%d\n", len(shareBytes))

		kf := goethkey.Keyfile{}

		kf.Crypto.Kdf = kdfNew
		var pass,p2 []byte
		var err error
		for true {
			pass, err = readPassword("Password for the keyfile:")
			if err != nil {fmt.Println(err); return}
			p2, err = readPassword("Repeat password:")
			if err != nil {fmt.Println(err); return}
			if len(pass) < 6 {fmt.Println("Password too short, try again\n"); continue}
			if bytes.Equal(pass,p2) {break}
			fmt.Println("Passwords do not match, try again\n")
		}

		//Derive the key from password
		var key []byte
		salt := make([]byte,16)
		rand.Read(salt)
		/*
			kf.Crypto.KdfparamsPack.Dklen=32
			kf.Crypto.KdfparamsPack.N=131072
			kf.Crypto.KdfparamsPack.P=1
			kf.Crypto.KdfparamsPack.R=8
			kf.Crypto.KdfparamsPack.Salt=hex.EncodeToString(salt)
		*/
		switch kdfNew {
		case "scrypt":
			kf.Crypto.KdfScryptParams.Dklen=32
			kf.Crypto.KdfScryptParams.N=131072
			kf.Crypto.KdfScryptParams.P=1
			kf.Crypto.KdfScryptParams.R=8
			kf.Crypto.KdfScryptParams.Salt=hex.EncodeToString(salt)
		default:
			fmt.Println("Unsupported KDF scheme")
			return
		}


		key, err = goethkey.KeyFromPassScrypt(pass, kf.Crypto.KdfScryptParams)
		if err != nil { fmt.Println(err) }

		//Letsencrypt
		iv := make([]byte, 16)
		ciphertext := make([]byte, 88)
		rand.Read(iv)

		block, err := aes.NewCipher(key[0:16])
		if err != nil { return}
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(ciphertext, shareBytes)

		kf.Crypto.Cipherparams.Iv=hex.EncodeToString(iv)
		kf.Crypto.Ciphertext=hex.EncodeToString(ciphertext)
		kf.Crypto.Cipher="aes-128-ctr"

		mac:=goethkey.Keccak256(append(key[16:], ciphertext...))
		kf.Crypto.Mac=hex.EncodeToString(mac)
		kf.Version=3
		//_, pubkeyec := btcec.PrivKeyFromBytes(btcec.S256(), ethkey)
		//pubkeyeth := append(pubkeyec.X.Bytes(), pubkeyec.Y.Bytes()...)

		x, y := btcec.S256().ScalarBaseMult(shareBytes)
		pubkeyeth := append(x.Bytes(), y.Bytes()...)
		fmt.Printf("Public key: %s\n", hex.EncodeToString(pubkeyeth))
		kecc := goethkey.Keccak256(pubkeyeth)
		addr := kecc[12:]

		kf.Address=hex.EncodeToString(addr)

		xuuid, err := uuid.NewUUID()
		kf.ID=xuuid.String()
		parambytes , err := json.Marshal( &kf.Crypto.KdfScryptParams)
		kf.Crypto.KdfparamsPack.UnmarshalJSON(parambytes)

		bytes, err := json.Marshal(&kf)
		if err != nil {fmt.Println(err); return}
		ioutil.WriteFile(genFilenameBase + strconv.Itoa(i), bytes, 0644)
	}
}

func init() {
	rootCmd.AddCommand(generateKeySplitCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateKeyfileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateKeyfileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	generateKeySplitCmd.Flags().StringVarP(&kdfNew, "kdf", "", "scrypt", "--kdf preferredKDF")
}