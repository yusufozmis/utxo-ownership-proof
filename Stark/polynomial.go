package Stark

import (
	"fmt"
	"math/big"
)

type Polynomial struct {
	coeffs []FiniteFieldElement
}

func NewPolyFromFieldElement(f FiniteFieldElement) Polynomial {
	var result Polynomial
	result.coeffs = append(result.coeffs, f)
	return result
}
func NewPolyFromFieldArray(f []FiniteFieldElement) Polynomial {
	var result Polynomial
	result.coeffs = append(result.coeffs, f...)
	return result
}
func NewPolyFromInt64(f int64) Polynomial {
	bigInt := new(big.Int).SetInt64(f)
	fieldF := DefaultField.NewFieldElement(bigInt)
	fPoly := NewPolyFromFieldElement(fieldF)
	return fPoly
}
func (p Polynomial) Degree() int {
	deg := -1
	for i := range p.coeffs {
		if !p.coeffs[i].IsEqual(Zero) {
			deg = i
		}
	}
	return deg
}

func (p Polynomial) Neg() Polynomial {
	negCoeffs := make([]FiniteFieldElement, len(p.coeffs))
	for i, c := range p.coeffs {
		negCoeffs[i] = c.Negate()
	}
	return Polynomial{coeffs: negCoeffs}
}

func (p Polynomial) Add(q Polynomial) Polynomial {
	maxLen := max(len(p.coeffs), len(q.coeffs))
	newCoeffs := make([]FiniteFieldElement, maxLen)

	var field FiniteField = DefaultField
	for i := 0; i < maxLen; i++ {
		var a, b FiniteFieldElement

		if i < len(p.coeffs) {
			a = p.coeffs[i]
		} else {
			a = FiniteFieldElement{
				Value: new(big.Int),
				Field: field,
			}
		}
		if i < len(q.coeffs) {
			b = q.coeffs[i]
		} else {
			b = FiniteFieldElement{
				Value: new(big.Int),
				Field: field,
			}
		}
		newCoeffs[i] = a.Add(b)
	}
	return Polynomial{coeffs: newCoeffs}
}

func (p Polynomial) Sub(q Polynomial) Polynomial {
	return p.Add(q.Neg())
}

func (p Polynomial) Mul(q Polynomial) Polynomial {
	if len(p.coeffs) == 0 || len(q.coeffs) == 0 {
		return Polynomial{coeffs: []FiniteFieldElement{}}
	}
	t := len(p.coeffs)
	k := len(q.coeffs)
	buf := make([]FiniteFieldElement, t+k-1)
	for i := range buf {
		buf[i] = Zero
	}
	for i := 0; i < t; i++ {
		if p.coeffs[i].IsZero() {
			continue
		}
		for j := 0; j < k; j++ {
			buf[i+j] = buf[i+j].Add(p.coeffs[i].Mul(q.coeffs[j]))
		}
	}
	return Polynomial{coeffs: buf}
}
func (p Polynomial) ScalarMul(k FiniteFieldElement) Polynomial {
	if k.IsZero() {
		return Polynomial{coeffs: []FiniteFieldElement{Zero}}
	}

	var newCoeffs []FiniteFieldElement
	for _, coeff := range p.coeffs {
		newCoeffs = append(newCoeffs, coeff.Mul(k))
	}
	return Polynomial{coeffs: newCoeffs}
}

func (p Polynomial) IsEqual(q Polynomial) bool {
	if p.Degree() != q.Degree() {
		return false
	}
	t := p.Degree() + 1
	for i := 0; i < t; i++ {
		if !p.coeffs[i].IsEqual(q.coeffs[i]) {
			return false
		}
	}
	return true
}

func (p Polynomial) IsZero() bool {
	t := len(p.coeffs)
	for i := 0; i < t; i++ {
		if !p.coeffs[i].IsZero() {
			return false
		}
	}
	return true
}

func (p Polynomial) LeadingCoeff() FiniteFieldElement {
	t := p.Degree()
	if t != -1 {
		return p.coeffs[p.Degree()]
	}
	return Zero
}

func (numerator Polynomial) Divide(denominator Polynomial) (quotient, remainder Polynomial) {
	if denominator.Degree() == -1 {
		return Polynomial{}, Polynomial{}
	}
	if numerator.Degree() < denominator.Degree() {
		return Polynomial{coeffs: []FiniteFieldElement{Zero}}, numerator
	}
	remainder = Polynomial{
		coeffs: make([]FiniteFieldElement, len(numerator.coeffs)),
	}
	for i := range numerator.coeffs {
		remainder.coeffs[i] = FiniteFieldElement{
			Value: new(big.Int).Set(numerator.coeffs[i].Value),
			Field: numerator.coeffs[i].Field,
		}
	}
	quotientSize := numerator.Degree() - denominator.Degree() + 1
	quotientCoeffs := make([]FiniteFieldElement, quotientSize)
	for i := range quotientCoeffs {
		quotientCoeffs[i] = FiniteFieldElement{
			Value: new(big.Int),
			Field: numerator.coeffs[0].Field,
		}
	}
	for remainder.Degree() >= denominator.Degree() {
		coefficient := remainder.LeadingCoeff().Division(denominator.LeadingCoeff())

		shift := remainder.Degree() - denominator.Degree()

		shiftedCoeffs := make([]FiniteFieldElement, shift+1)
		for i := range shiftedCoeffs {
			shiftedCoeffs[i] = FiniteFieldElement{
				Value: new(big.Int),
				Field: numerator.coeffs[0].Field,
			}
		}
		shiftedCoeffs[shift] = coefficient

		subtractee := Polynomial{coeffs: shiftedCoeffs}.Mul(denominator)

		quotientCoeffs[shift] = coefficient
		remainder = remainder.Sub(subtractee)
	}

	quotient = Polynomial{coeffs: quotientCoeffs}
	return quotient, remainder
}

func (p Polynomial) Exp(exponent FiniteFieldElement) Polynomial {

	if exponent.IsZero() {
		return Polynomial{coeffs: []FiniteFieldElement{One}}
	}
	if p.IsZero() {
		return Polynomial{}
	}

	acc := Polynomial{coeffs: []FiniteFieldElement{One}}
	t := exponent.Value
	for i := t.BitLen() - 1; i >= 0; i-- {
		acc = acc.Mul(acc)
		if t.Bit(i) == 1 {
			acc = acc.Mul(p)
		}
	}
	return acc
}

func (p Polynomial) Evaluate(point FiniteFieldElement) FiniteFieldElement {
	xi := One
	value := Zero
	for i, coeff := range p.coeffs {
		if coeff.Value == nil {
			fmt.Printf("Coefficient at index %d has nil value\n", i)
		}
		value = value.Add(coeff.Mul(xi))
		xi = xi.Mul(point)
	}
	return value
}
func (p Polynomial) EvaluateDomain(points []FiniteFieldElement) []FiniteFieldElement {
	var results []FiniteFieldElement
	for _, point := range points {
		f := p.Evaluate(point)
		results = append(results, f)
	}
	return results
}
func (p Polynomial) Compose(q Polynomial) Polynomial {
	result := Polynomial{coeffs: []FiniteFieldElement{Zero}}
	for i, coeff := range p.coeffs {
		term := q.Exp(FiniteFieldElement{Value: big.NewInt(int64(i)), Field: DefaultField})
		term = term.Mul(Polynomial{coeffs: []FiniteFieldElement{coeff}})
		result = result.Add(term)
	}
	return result
}
func (p Polynomial) TrueDiv(denominator Polynomial) (Polynomial, error) {
	quotient, remainder := p.Divide(denominator)
	if quotient.IsZero() {
		return Polynomial{}, fmt.Errorf("Remainder is not zero")
	}
	return remainder, nil
}
func Interpolation(domain, values []FiniteFieldElement) Polynomial {

	if len(domain) != len(values) {
		panic("number of elements in domain does not match number of values -- cannot interpolate")
	}
	if len(domain) == 0 {
		panic("cannot interpolate between zero points")
	}
	acc := Polynomial{coeffs: []FiniteFieldElement{}}
	t := len(domain)
	for i := 0; i < t; i++ {
		prod := Polynomial{coeffs: []FiniteFieldElement{values[i]}}

		for j := 0; j < t; j++ {
			if j == i {
				continue
			}
			xMinusXj := Polynomial{coeffs: []FiniteFieldElement{domain[j].Negate(), One}}

			denomInverse := domain[i].Sub(domain[j]).Inverse()

			prod = prod.Mul(xMinusXj).Mul(Polynomial{coeffs: []FiniteFieldElement{denomInverse}})
		}
		acc = acc.Add(prod)
	}
	return acc
}
