package Stark

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"utxo-ownership-proof/Bitcoin"
	common "utxo-ownership-proof/Common"

	"github.com/btcsuite/btcd/wire"
)

var generator FiniteFieldElement = FiniteFieldElement{Value: big.NewInt(5), Field: DefaultField}

var g FiniteFieldElement = generator.Exp(FiniteFieldElement{
	Value: big.NewInt(3 * (1 << 20)),
	Field: DefaultField,
})

func Domain() []FiniteFieldElement {

	var genExp []FiniteFieldElement
	var b FiniteFieldElement = One
	for i := 0; i < 1024; i++ {
		genExp = append(genExp, b)
		b = b.Mul(g)
	}
	b = One
	for i := 0; i < 1023; i++ {
		if !b.IsEqual(genExp[i]) {
			panic("The i-th place in G is not equal to the i-th power of g.")
		}
		b = b.Mul(g)
		if b.IsEqual(One) {
			panic("invalid")
		}
	}
	return genExp
}

func VanishingPolynomial(domain []FiniteFieldElement) Polynomial {
	result := Polynomial{coeffs: []FiniteFieldElement{One}}
	for _, point := range domain {
		factor := Polynomial{coeffs: []FiniteFieldElement{point.Negate(), One}}
		result = result.Mul(factor)
	}
	return result
}

// Asserts the equality of two given strings.
func AssertEqual(a, b string) Polynomial {
	aBytes, err := hex.DecodeString(a)
	if err != nil {
		panic("Invalid hex string for a: " + a)
	}
	bBytes, err := hex.DecodeString(b)
	if err != nil {
		panic("Invalid hex string for b: " + b)
	}

	aBigInt := new(big.Int).SetBytes(aBytes)
	bBigInt := new(big.Int).SetBytes(bBytes)

	aField := DefaultField.NewFieldElement(aBigInt)
	bField := DefaultField.NewFieldElement(bBigInt)

	aPoly := Polynomial{coeffs: []FiniteFieldElement{aField}}
	bPoly := Polynomial{coeffs: []FiniteFieldElement{bField}}
	poly := aPoly.Sub(bPoly)

	if !poly.IsZero() {
		panic("Not Equal. Constraint Not Satisfied")
	}

	return poly
}

// Asserts the equality of two given integers.
func AssertEqualInteger(a, b int64) Polynomial {

	aBigInt := new(big.Int).SetInt64(a)
	bBigInt := new(big.Int).SetInt64(b)

	aField := DefaultField.NewFieldElement(aBigInt)
	bField := DefaultField.NewFieldElement(bBigInt)

	aPoly := Polynomial{coeffs: []FiniteFieldElement{aField}}
	bPoly := Polynomial{coeffs: []FiniteFieldElement{bField}}
	poly := aPoly.Sub(bPoly)

	if !poly.IsZero() {
		panic("Not Equal. Constraint Not Satisfied")
	}

	constraint, _ := poly.TrueDiv(vanishingPoly)
	if !constraint.IsZero() {
		panic("Constraint not satisfied")
	}
	return constraint
}

// Asserts that given two strings are NOT equal.
func AssertNotEqual(a, b string) Polynomial {
	aBigInt := new(big.Int).SetBytes([]byte(a))
	bBigInt := new(big.Int).SetBytes([]byte(b))

	aField := DefaultField.NewFieldElement(aBigInt)
	bField := DefaultField.NewFieldElement(bBigInt)
	aPoly := Polynomial{coeffs: []FiniteFieldElement{aField}}
	bPoly := Polynomial{coeffs: []FiniteFieldElement{bField}}
	poly := aPoly.Sub(bPoly)

	if poly.IsZero() {
		panic("Values are equal — NotEqual constraint failed")
	}

	return poly
}

// Proves that a given Merkle Tree is constructed correctly
func ProveMerkleTree(tree [][]string, root string) []Polynomial {

	var constraints []Polynomial
	var computedRoot string

	for level := 0; level < len(tree)-1; level++ {
		leaves := tree[level]
		parents := tree[level+1]

		parentIndex := 0

		for i := 0; i < len(leaves); i += 2 {
			var left, right []byte
			leftBytes, err := hex.DecodeString(leaves[i])
			if err != nil {
				fmt.Println("Bad hex at level", level, "index", i, "value:", leaves[i])
				panic("invalid hex in leaves")
			}

			if i+1 < len(leaves) {
				rightBytes, err := hex.DecodeString(leaves[i+1])
				if err != nil {
					fmt.Println("Bad hex at level (this is i+1<len(leaves) check)", level, "index", i, "value:", leaves[i])
					panic("invalid hex in leaves")
				}
				left = leftBytes
				right = rightBytes
			} else {
				left = leftBytes
				right = leftBytes
			}

			combined := append(left, right...)
			hashed := Bitcoin.DoubleSHA256(combined)
			expectedParent := hex.EncodeToString(hashed)

			constr := AssertEqual(expectedParent, parents[parentIndex])
			constraints = append(constraints, constr)

			parentIndex++
		}
		if level == len(tree)-2 {
			computedRoot = parents[0]
		}
	}

	rootBytes, _ := hex.DecodeString(computedRoot)
	rootBytes = Bitcoin.ReverseBytes(rootBytes)

	computedRoot = hex.EncodeToString(rootBytes)

	constr := AssertEqual(computedRoot, root)
	constraints = append(constraints, constr)

	return constraints

}

// This  function takes the raw transacion and proves that a given vin.txid and vin.vout is in that rawhex (it removes the witness)
func ProveVin(rawHex string, Vin common.VinReference) []Polynomial {

	var ConstraintPolynomial []Polynomial
	trace := Bitcoin.TraceConcatVins(rawHex)

	var TraceFlatten []byte
	for _, txpart := range trace {
		TraceFlatten = append(TraceFlatten, txpart...)
	}
	flattenTrace := hex.EncodeToString(TraceFlatten)

	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.Deserialize(bytes.NewReader(rawBytes))
	var buf bytes.Buffer
	tx.SerializeNoWitness(&buf)
	rawtx := hex.EncodeToString(buf.Bytes())

	constr1 := AssertEqual(rawtx, flattenTrace)

	ConstraintPolynomial = append(ConstraintPolynomial, constr1)

	t := len(trace)
	domain := domain[:t]
	fieldTrace := BytesToField(trace)
	poly := Interpolation(domain, fieldTrace)
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, uint32(Vin.Vout))

	txid, _ := hex.DecodeString(Vin.Txid)
	txid = Bitcoin.ReverseBytes(txid)
	txidReverse := hex.EncodeToString(txid)

	var concat string
	concat += txidReverse
	concat += hex.EncodeToString(bytes)
	bigIntConcat, success := new(big.Int).SetString(concat, 16)
	if !success {
		panic("Error converting concat string to big.Int")
	}
	concatToField := DefaultField.NewFieldElement(bigIntConcat)
	var XValue FiniteFieldElement
	for i := 0; i < len(poly.coeffs); i++ {
		ff := poly.Evaluate(domain[i])
		if ff.IsEqual(concatToField) {
			XValue = domain[i]
		}
	}
	if XValue.Value == nil {
		panic("Constraint Not Satisfied. This Vin is not from given tx")
	}

	poly = poly.Sub(NewPolyFromFieldElement(concatToField))

	negX := []FiniteFieldElement{concatToField.Negate(), One}

	poly, _ = poly.Divide(NewPolyFromFieldArray(negX))
	poly, _ = poly.Divide(vanishingPoly)
	ConstraintPolynomial = append(ConstraintPolynomial, poly)
	return ConstraintPolynomial
}

func ProveBalanceAndPublicKey(rawHex string, Utxo common.Witness) []Polynomial {

	var ConstraintPolynomial []Polynomial
	trace := Bitcoin.TraceConcatAll(rawHex)

	var TraceFlatten []byte
	for _, txpart := range trace {
		TraceFlatten = append(TraceFlatten, txpart...)
	}
	flattenTrace := hex.EncodeToString(TraceFlatten)

	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.Deserialize(bytes.NewReader(rawBytes))
	var buf bytes.Buffer
	tx.SerializeNoWitness(&buf)
	rawtx := hex.EncodeToString(buf.Bytes())

	constr1 := AssertEqual(rawtx, flattenTrace)

	ConstraintPolynomial = append(ConstraintPolynomial, constr1)

	if len(trace[1]) != 1 {
		panic("error in trace")
	}
	inputCount := int(trace[1][0])
	voutCount := 3 + inputCount + Utxo.Vout

	XPoint := DefaultField.NewFieldElement(new(big.Int).SetInt64(int64(voutCount)))
	XPoint = g.Exp(XPoint)

	t := len(trace)
	domain := domain[:t]
	fieldTrace := BytesToField(trace)
	poly := Interpolation(domain, fieldTrace)

	balance := uint64(Utxo.Amount)
	bufBalance := make([]byte, 8)
	binary.LittleEndian.PutUint64(bufBalance, balance)
	hexBalance := hex.EncodeToString(bufBalance)

	var concat string
	concat += hexBalance
	concat += "19" // Prover only works for P2PKH outputs. This value of 19 in hex, corresponds to 25, lenght of a p2pkh pkscript
	concat += Utxo.P2PKHScript

	fmt.Println("concat:", concat)

	concatBigInt, success := new(big.Int).SetString(concat, 16)
	if !success {
		panic("err in concat to big int")
	}

	concatToField := DefaultField.NewFieldElement(concatBigInt)

	poly = poly.Sub(NewPolyFromFieldElement(concatToField))
	if !poly.Evaluate(XPoint).IsZero() {
		panic("poly is not zero")
	}

	negX := []FiniteFieldElement{concatToField.Negate(), One}

	poly, _ = poly.Divide(NewPolyFromFieldArray(negX))
	poly, _ = poly.Divide(vanishingPoly)

	ConstraintPolynomial = append(ConstraintPolynomial, poly)
	return ConstraintPolynomial

}

// Proves that a given Vout exists in the utxo
func ProveVout(rawHex string, Utxo common.Witness) []Polynomial {

	var ConstraintPolynomial []Polynomial
	trace := Bitcoin.TraceConcatAll(rawHex)
	var TraceFlatten []byte
	for _, txpart := range trace {
		TraceFlatten = append(TraceFlatten, txpart...)
	}
	flattenTrace := hex.EncodeToString(TraceFlatten)

	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.Deserialize(bytes.NewReader(rawBytes))
	var buf bytes.Buffer
	tx.SerializeNoWitness(&buf)
	rawtx := hex.EncodeToString(buf.Bytes())

	constr1 := AssertEqual(rawtx, flattenTrace)

	ConstraintPolynomial = append(ConstraintPolynomial, constr1)

	if len(trace[1]) != 1 {
		panic("error in trace")
	}
	inputCount := int(trace[1][0])
	voutCount := 2 + inputCount

	constr2 := AssertEqualInteger(int64(voutCount), int64(len(trace[voutCount:len(trace)-1])))

	ConstraintPolynomial = append(ConstraintPolynomial, constr2)

	constr3 := AssertGreaterThan(Utxo.Vout, voutCount)

	ConstraintPolynomial = append(ConstraintPolynomial, constr3...)

	return ConstraintPolynomial
}

// Proves that a given Rawtx corresponds to the given txid
func ProveRawTx(rawhex string, txid string) Polynomial {

	rawTxBytes, err := hex.DecodeString(rawhex)
	if err != nil {
		panic(fmt.Errorf("failed to decode hex: %w", err))
	}

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(rawTxBytes))
	if err != nil {
		panic(fmt.Errorf("failed to deserialize transaction: %w", err))
	}

	var buf bytes.Buffer
	err = msgTx.SerializeNoWitness(&buf)
	if err != nil {
		panic(fmt.Errorf("failed to serialize without witness: %w", err))
	}
	serializedNoWitness := buf.Bytes()

	hash := Bitcoin.DoubleSHA256(serializedNoWitness)

	hash = Bitcoin.ReverseBytes(hash[:])

	expectedTxid := hex.EncodeToString(hash)

	constr := AssertEqual(expectedTxid, txid)

	return constr
}

// Proves the validity of a given Merkle Proof
func MerkleProofStark(proof []string, leaf string, pos int) Polynomial {
	trace := Bitcoin.MerkleTrace(proof, leaf, pos)
	expectedLength := 2*len(proof) + 1
	if len(trace) != expectedLength {
		panic(fmt.Sprintf("Trace length mismatch: expected", expectedLength, "got", len(trace)))
	}

	currentPos := pos
	firstHashBytes, err := hex.DecodeString(trace[0])
	if err != nil {
		panic(fmt.Sprintf("Invalid trace hex at position 0: %s", trace[0]))
	}
	currentHash := Bitcoin.ReverseBytes(firstHashBytes)
	poly := Polynomial{coeffs: []FiniteFieldElement{One}}
	for i := 0; i < len(proof); i++ {
		siblingBytes, err := hex.DecodeString(proof[i])
		if err != nil {
			panic(fmt.Sprintf("Invalid sibling hex:", proof[i]))
		}

		poly = poly.Mul(AssertEqual(proof[i], trace[2*i+1]))

		siblingInternal := Bitcoin.ReverseBytes(siblingBytes)
		var combined []byte
		if currentPos%2 == 0 {
			combined = append(currentHash, siblingInternal...)
		} else {
			combined = append(siblingInternal, currentHash...)
		}

		first := sha256.Sum256(combined)
		second := sha256.Sum256(first[:])
		currentHash = second[:]

		resultHashBytes, err := hex.DecodeString(trace[2*i+2])
		if err != nil {
			panic(fmt.Sprintf("Invalid trace hash at step", i, ":", trace[2*i+2]))
		}
		expectedHashDisplay := Bitcoin.ReverseBytes(currentHash)
		t := fmt.Sprintf("%x", expectedHashDisplay)

		poly = poly.Mul(AssertEqual(t, trace[2*i+2]))
		if i < len(proof)-1 {
			currentHash = Bitcoin.ReverseBytes(resultHashBytes)
		}
		currentPos /= 2
	}
	return poly
}

func CompositionPolynomial(ch *Channel, c []Polynomial) Polynomial {

	var cp Polynomial
	cp.coeffs = append(cp.coeffs, Zero)
	for i := 0; i < len(c); i++ {
		alpha := ch.ReceiveRandomFieldElement()
		t := c[i].ScalarMul(alpha)
		cp = cp.Add(t)
	}

	return cp
}
