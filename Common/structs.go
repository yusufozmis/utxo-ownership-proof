package common

type Witness struct {
	Txid        string
	Vout        int
	Amount      int
	GivenAmount int
	P2PKHScript string
}
type VinReference struct {
	Txid string
	Vout int
}
