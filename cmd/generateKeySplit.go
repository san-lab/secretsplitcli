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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/uuid"
	"github.com/san-lab/secretsplitcli/goethkey"
	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

// generateKeyfileCmd represents the generateKeyfile command
var generateKeySplitCmd = &cobra.Command{
	Use:   "generateKeySplit totalShares MinShares baseFilename privatekey",
	Short: "Generates shamir secret shares of a private key",
	Long:  `Generates shamir secret shares of a private key. Interactively asks for passwords (do not forget your choice!).`,
	Run:   generateKeySplit,
}

var numShares, minShares int
var genFilenameBase string
var kdfNew string

var ethkeyStr string
var ethkey []byte

//var DefaultPrimeStr = "115792089237316195423570985008687907853269984665640564039457584007913129639747"
//var defaultPrime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

func generateKeySplit(cmd *cobra.Command, args []string) {
	if numShares > 255 || minShares > numShares {
		fmt.Println("Invalid split parameters:", numShares, minShares)
		return
	}
	var poly *share.PriPoly
	if len(ethkeyStr) == 0 {

		fmt.Printf("Generating %v of %v split of a new random key\n", minShares, numShares)

		suite := suites.MustFind("bn256.G2")
		secretScalar := pairing.NewSuiteBn256().G2().Scalar().Pick(suite.RandomStream())
		poly = share.NewPriPoly(pairing.NewSuiteBn256().G2(), minShares, secretScalar, pairing.NewSuiteBn256().RandomStream())
		fmt.Println("Secret key", secretScalar)
	} else {
		fmt.Printf("Generating %v of %v split of the key provided\n", minShares, numShares)
		ethkey, err := hex.DecodeString(ethkeyStr)
		if err != nil {
			fmt.Println(err)
			return
		}
		secretScalar := pairing.NewSuiteBn256().G2().Scalar().SetBytes(ethkey)
		poly = share.NewPriPoly(pairing.NewSuiteBn256().G2(), minShares, secretScalar, pairing.NewSuiteBn256().RandomStream())
		fmt.Println("Secret scalar", secretScalar)
	}

	sharesN := poly.Shares(numShares)

	var arrayShareBytes [][]byte
	for _, s := range sharesN {
		b, err := goethkey.MarshalHEX(s)
		if err != nil {
			fmt.Println(err)
			return
		}
		arrayShareBytes = append(arrayShareBytes, b)
	}
	xuuid, err := uuid.NewUUID()
	if err != nil {
		fmt.Println(err)
		return
	}
	for i := 0; i < len(arrayShareBytes); i++ {
		keyFileName := fmt.Sprintf("%s%vof%v.json", genFilenameBase, i+1, numShares)
		fmt.Printf("Generating keyfile No %v (%s)\n", i+1, keyFileName)
		shareBytes := arrayShareBytes[i]
		kf := goethkey.Keyfile{}

		kf.Crypto.Kdf = kdfNew

		pass, err := goethkey.SetPassword()
		if err != nil {
			fmt.Println(err)
			return
		}

		salt := make([]byte, 16)
		rand.Read(salt)
		/*
			kf.Crypto.KdfparamsPack.Dklen=32
			kf.Crypto.KdfparamsPack.N=131072
			kf.Crypto.KdfparamsPack.P=1
			kf.Crypto.KdfparamsPack.R=8
			kf.Crypto.KdfparamsPack.Salt=hex.EncodeToString(salt)
		*/
		switch kdf {
		case "scrypt":
			kf.Crypto.KdfScryptParams.Dklen = 32
			kf.Crypto.KdfScryptParams.N = 131072
			kf.Crypto.KdfScryptParams.P = 1
			kf.Crypto.KdfScryptParams.R = 8
			kf.Crypto.KdfScryptParams.Salt = hex.EncodeToString(salt)
		default:
			fmt.Println("Unsupported KDF scheme")
			return
		}

		err = goethkey.EncryptAES128(&kf, shareBytes, pass)

		kf.Address = "NaN"
		kf.ID = goethkey.SplitHeader + hex.EncodeToString([]byte{byte(minShares)}) + hex.EncodeToString([]byte{byte(i)}) + "-" + xuuid.String()

		bytes, err := json.Marshal(&kf)
		if err != nil {
			fmt.Println(err)
			return
		}
		ioutil.WriteFile(keyFileName, bytes, 0644)
		fmt.Printf("File %s generated successfully\n", keyFileName)
	}
	fmt.Println("Private key correctly split and stored!!")
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
	generateKeySplitCmd.Flags().IntVarP(&numShares, "shares", "s", 3, "--shares \tTotal number of shares of the secret")
	generateKeySplitCmd.Flags().IntVarP(&minShares, "threshold", "t", 2, "--threshold  \tSecret recovery threshold")
	generateKeySplitCmd.Flags().StringVarP(&genFilenameBase, "filename", "f", "splitkeyfile", "--filename \tFile base name")
	generateKeySplitCmd.Flags().StringVarP(&ethkeyStr, "ethkey", "e", "", "--ethkey \tSecret to be split")
}
