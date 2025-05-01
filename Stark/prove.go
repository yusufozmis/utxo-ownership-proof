package Stark

import (
	"utxo-ownership-proof/Bitcoin"
	common "utxo-ownership-proof/Common"
)

var vanishingPoly Polynomial = VanishingPolynomial(EvalDomain())

var domain []FiniteFieldElement = Domain()

func Prove(tx common.Witness) []string {

	rawTx := Bitcoin.RawTx(tx.Txid)
	spv := Bitcoin.GetInclusion(tx.Txid)

	ch := NewChannel()
	domain := EvalDomain()
	vanishRoot := MerkleRoot(MerkleTree(vanishingPoly.coeffs))
	ch.Send(vanishRoot.hash)

	var ConstraintPolynomials []Polynomial

	inclusionConstraint := MerkleProofStark(spv.InclusionProof, tx.Txid, spv.Pos)
	rawTxidConstraint := ProveRawTx(rawTx, tx.Txid)

	ownershipConstraint := ProveBalanceAndPublicKey(rawTx, tx)
	amountConstraint := AssertGreaterThan(tx.Amount, tx.GivenAmount)

	unspentConstraint := UnspentProof(ch, spv.BlockHeight, tx)

	ConstraintPolynomials = append(ConstraintPolynomials, inclusionConstraint)
	ConstraintPolynomials = append(ConstraintPolynomials, rawTxidConstraint)
	ConstraintPolynomials = append(ConstraintPolynomials, ownershipConstraint...)
	ConstraintPolynomials = append(ConstraintPolynomials, amountConstraint...)
	ConstraintPolynomials = append(ConstraintPolynomials, unspentConstraint...)

	cp := CompositionPolynomial(ch, ConstraintPolynomials)

	var randomPoly Polynomial
	for i := 0; i <= 2; i++ {
		alpha := ch.ReceiveRandomFieldElement()
		randomPoly.coeffs = append(randomPoly.coeffs, alpha)
	}
	noise := randomPoly.Mul(vanishingPoly)

	cp = cp.Add(noise)

	cp, _ = cp.TrueDiv(vanishingPoly)

	polyEvaluated := cp.EvaluateDomain(EvalDomain())
	tree := MerkleTree(polyEvaluated)
	root := MerkleRoot(tree)
	ch.Send(root.hash)

	_, _, frilayers, frimerkles := FriCommit(cp, domain, polyEvaluated, ch, tree)

	DecommitFRI(ch, cp, frilayers, frimerkles)

	return ch.proof
}
