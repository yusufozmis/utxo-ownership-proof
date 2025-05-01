package Stark

import (
	"math/big"
	"strings"
)

func EvalDomain() []FiniteFieldElement {
	exponent := new(big.Int).Mul(big.NewInt(3), new(big.Int).Lsh(big.NewInt(1), 30))
	exponent = new(big.Int).Div(exponent, big.NewInt(8192))

	var h_gen FiniteFieldElement = generator.Exp(FiniteFieldElement{
		Value: exponent,
		Field: DefaultField,
	})
	var h []FiniteFieldElement
	for i := 0; i < 8192; i++ {
		t := h_gen.Exp(FiniteFieldElement{Value: big.NewInt(int64(i)), Field: DefaultField})
		h = append(h, t)
	}
	var domain []FiniteFieldElement
	for _, val := range h {
		k := generator.Mul(val)
		domain = append(domain, k)
	}
	return domain
}

func nextFRIdomain(fri_domain []FiniteFieldElement) []FiniteFieldElement {
	t := len(fri_domain)
	newDomain := make([]FiniteFieldElement, t/2)
	for i := 0; i < t/2; i++ {
		newDomain[i] = fri_domain[i].Exp(Two)
	}
	return newDomain
}

func nextFRIPolynomial(p Polynomial, beta FiniteFieldElement) Polynomial {
	oddPoly := OddCoeffs(p)
	evenPoly := EvenCoeffs(p)
	for i := range oddPoly.coeffs {
		oddPoly.coeffs[i] = oddPoly.coeffs[i].Mul(beta)
	}
	result := evenPoly.Add(oddPoly)
	return result
}

func OddCoeffs(p Polynomial) Polynomial {
	t := len(p.coeffs)
	var oddCoeffs []FiniteFieldElement
	for i := 1; i < t; i += 2 {
		oddCoeffs = append(oddCoeffs, p.coeffs[i])
	}
	return Polynomial{coeffs: oddCoeffs}
}

func EvenCoeffs(p Polynomial) Polynomial {
	t := len(p.coeffs)
	var evenCoeffs []FiniteFieldElement
	for i := 0; i < t; i += 2 {
		evenCoeffs = append(evenCoeffs, p.coeffs[i])
	}
	return Polynomial{coeffs: evenCoeffs}
}

func NextFRILayer(poly Polynomial, domain []FiniteFieldElement, Beta FiniteFieldElement) (Polynomial, []FiniteFieldElement, []FiniteFieldElement) {
	next_poly := nextFRIPolynomial(poly, Beta)
	next_domain := nextFRIdomain(domain)
	var nextLayer []FiniteFieldElement
	for _, val := range next_domain {
		eval := next_poly.Evaluate(val)
		nextLayer = append(nextLayer, eval)
	}
	return next_poly, next_domain, nextLayer
}

func FriCommit(cp Polynomial, domain []FiniteFieldElement, cp_eval []FiniteFieldElement, ch *Channel, cp_merkle [][]Node) ([]Polynomial, [][]FiniteFieldElement, [][]FiniteFieldElement, [][][]Node) {
	var fripolys []Polynomial
	fripolys = append(fripolys, cp)
	var fridomains [][]FiniteFieldElement
	fridomains = append(fridomains, domain)
	var frilayers [][]FiniteFieldElement
	frilayers = append(frilayers, cp_eval)
	var frimerkles [][][]Node
	frimerkles = append(frimerkles, cp_merkle)
	for fripolys[len(fripolys)-1].Degree() > 0 {
		beta := ch.ReceiveRandomFieldElement()
		t := len(fripolys)
		k := len(fridomains)

		nextPoly, nextDomain, nextLayer := NextFRILayer(fripolys[t-1], fridomains[k-1], beta)
		fripolys = append(fripolys, nextPoly)
		fridomains = append(fridomains, nextDomain)
		frilayers = append(frilayers, nextLayer)
		frimerkles = append(frimerkles, MerkleTree(nextLayer))
		ch.Send(MerkleRoot(frimerkles[len(frimerkles)-1]).hash)
	}
	t := FiniteFieldElement{Value: fripolys[len(fripolys)-1].coeffs[0].Value, Field: DefaultField}
	ch.Send(t.Value.String())
	return fripolys, fridomains, frilayers, frimerkles
}
func DecommitFriLayer(idx int, ch *Channel, friLayers [][]FiniteFieldElement, friMerkles [][][]Node) {
	for i := 0; i < len(friLayers)-1; i++ {
		layer := friLayers[i]
		merkle := friMerkles[i]

		length := len(layer)
		idx = idx % length
		sib_idx := (idx + length/2) % length

		ch.Send(layer[idx].Value.String())
		merkleidx := MerkleProof(merkle, idx)
		l := len(merkleidx)
		merkleidxreversed := make([]string, l)
		for i := range merkleidx {
			merkleidxreversed[i] = merkleidx[l-i-1]
		}
		merklequoted := strings.Join(merkleidxreversed, " ")
		ch.Send(merklequoted)
		ch.Send(layer[sib_idx].Value.String())
		merkleproof := MerkleProof(merkle, sib_idx)
		t := len(merkleproof)
		merkleproofreversed := make([]string, t)
		for i := range merkleproof {
			merkleproofreversed[i] = merkleproof[t-1-i]
		}
		merklequoted2 := strings.Join(merkleproofreversed, " ")
		ch.Send(merklequoted2)
	}
	ch.Send(friLayers[len(friLayers)-1][0].Value.String())
}

func DecommitOnQuery(idx int, ch *Channel, poly Polynomial, friLayers [][]FiniteFieldElement, friMerkles [][][]Node) {
	domain := EvalDomain()
	f_eval := poly.EvaluateDomain(domain)
	merkleTree := MerkleTree(f_eval)
	if idx+16 >= len(f_eval) {
		panic("idx is out of range")
	}
	ch.Send(f_eval[idx].Value.String())

	firstMerkleProof := MerkleProof(merkleTree, idx)
	ch.Send(strings.Join(firstMerkleProof, " "))

	ch.Send(f_eval[idx+8].Value.String())
	secondMerkleProof := MerkleProof(merkleTree, idx+8)
	ch.Send(strings.Join(secondMerkleProof, " "))

	ch.Send(f_eval[idx+16].Value.String())
	thirdMerkleProof := MerkleProof(merkleTree, idx+16)
	ch.Send(strings.Join(thirdMerkleProof, " "))

	DecommitFriLayer(idx, ch, friLayers, friMerkles)
}

func DecommitFRI(ch *Channel, poly Polynomial, frilayers [][]FiniteFieldElement, frimerkles [][][]Node) {
	lowerBound := big.NewInt(0)
	upperBound := big.NewInt(8191 - 16)

	for query := 0; query < 3; query++ {
		t := ch.ReceiveRandomInt(lowerBound, upperBound)
		DecommitOnQuery(int(t.Int64()), ch, poly, frilayers, frimerkles)
	}
}
