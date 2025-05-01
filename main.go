package main

import (
	"fmt"
	"utxo-ownership-proof/Bitcoin"
	common "utxo-ownership-proof/Common"
	"utxo-ownership-proof/Stark"
)

func main() {

	mnemonic := "" //your mnemonic

	publicKeyHash := Bitcoin.PublicKeyHash(mnemonic) // Computes PublicKeyHash for a P2PKH output

	var tx common.Witness
	tx.Txid = ""         //Txid of your UTXO
	tx.Vout = 5          //Vout of your UTXO
	tx.Amount = 101      // the amount of satoshi's you own
	tx.GivenAmount = 100 //The Amount you'll prove you have more than. In this example, you prove that you have more than 100 satoshis.
	tx.P2PKHScript = Bitcoin.P2PKHScript(publicKeyHash)

	proof := Stark.Prove(tx)
	fmt.Println("proof", proof)

}
