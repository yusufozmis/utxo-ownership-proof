package Stark

import (
	"fmt"
	"math/big"
)

func IntToBits(x int) []int {
	bits := make([]int, 32)
	for i := 31; i >= 0; i-- {
		bits[i] = x & 1
		x >>= 1
	}
	return bits
}

func IntToBytes(x int) []byte {
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		bytes[3-i] = byte(x & 0xFF)
		x >>= 8
	}
	return bytes
}

// Proves that a given integer array includes only bits (0 and 1)
func CheckBitConstraint(x []int) []Polynomial {

	var Constraints []Polynomial
	for _, xBit := range x {

		xField := DefaultField.NewFieldElement(new(big.Int).SetInt64(int64(xBit)))
		f1 := []FiniteFieldElement{Zero, xField}
		f2 := []FiniteFieldElement{One.Negate(), xField}

		f1Poly := NewPolyFromFieldArray(f1)
		f2Poly := NewPolyFromFieldArray(f2)

		poly := f1Poly.Mul(f2Poly)

		if !poly.Evaluate(One).IsZero() {
			fmt.Println("not a bit value")
		}
		Constraints = append(Constraints, poly)

	}
	return Constraints
}

func BitEqualPoly(xBit, yBit int) (Polynomial, []Polynomial) {
	var constraints []Polynomial

	xPoly := NewPolyFromInt64(int64(xBit))
	yPoly := NewPolyFromInt64(int64(yBit))

	diff := xPoly.Sub(yPoly)
	diffSquared := diff.Mul(diff)
	one := NewPolyFromFieldElement(One)
	equal := one.Sub(diffSquared)

	constraints = append(constraints, xPoly.Mul(xPoly.Sub(one)))
	constraints = append(constraints, yPoly.Mul(yPoly.Sub(one)))

	return equal, constraints
}

func GTBitPoly(xBit, yBit int) (Polynomial, []Polynomial) {
	var constraints []Polynomial

	xPoly := NewPolyFromInt64(int64(xBit))
	yPoly := NewPolyFromInt64(int64(yBit))

	one := NewPolyFromFieldElement(One)
	oneMinusY := one.Sub(yPoly)

	gt := xPoly.Mul(oneMinusY)

	constraints = append(constraints, xPoly.Mul(xPoly.Sub(one)))
	constraints = append(constraints, yPoly.Mul(yPoly.Sub(one)))

	return gt, constraints
}

// Proves that x > y
func AssertGreaterThan(x, y int) []Polynomial {
	var constraints []Polynomial

	xBits := IntToBits(x)
	yBits := IntToBits(y)

	xBitsConstraint := CheckBitConstraint(xBits)
	yBitsConstraint := CheckBitConstraint(yBits)

	constraints = append(constraints, xBitsConstraint...)
	constraints = append(constraints, yBitsConstraint...)

	t := 32
	sum := NewPolyFromFieldElement(Zero)

	for i := 0; i < t; i++ {
		prod := NewPolyFromFieldElement(One)
		for j := 0; j < i; j++ {
			equalPoly, equalConstraints := BitEqualPoly(xBits[j], yBits[j])
			prod = prod.Mul(equalPoly)
			constraints = append(constraints, equalConstraints...)
		}
		gtPoly, gtConstraints := GTBitPoly(xBits[i], yBits[i])
		constraints = append(constraints, gtConstraints...)

		contribution := prod.Mul(gtPoly)
		sum = sum.Add(contribution)
	}
	AssertEqualInteger(int64(sum.Degree()), 0)
	AssertEqualInteger(sum.LeadingCoeff().Value.Int64(), 1)

	return constraints
}
