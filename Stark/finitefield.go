package Stark

import "math/big"

type FiniteField struct {
	Prime *big.Int
}
type FiniteFieldElement struct {
	Value *big.Int
	Field FiniteField
}

var Zero = FiniteFieldElement{
	Value: big.NewInt(0),
	Field: DefaultField,
}
var One = FiniteFieldElement{
	Value: big.NewInt(1),
	Field: DefaultField,
}
var Two = FiniteFieldElement{
	Value: big.NewInt(2),
	Field: DefaultField,
}

var DefaultFieldSize = new(big.Int).Add(
	new(big.Int).Mul(
		big.NewInt(3),
		new(big.Int).Exp(big.NewInt(2), big.NewInt(30), nil),
	),
	big.NewInt(1),
)

var DefaultField = FiniteField{Prime: DefaultFieldSize}

func (f FiniteField) NewFieldElement(value *big.Int) FiniteFieldElement {
	modValue := new(big.Int).Mod(value, f.Prime)
	return FiniteFieldElement{Value: modValue, Field: f}
}
func (f FiniteFieldElement) Add(other FiniteFieldElement) FiniteFieldElement {
	if f.Field.Prime.Cmp(other.Field.Prime) != 0 {
		panic("Cannot add elements from different fields")
	}
	t := new(big.Int).Add(f.Value, other.Value)
	t.Mod(t, f.Field.Prime)
	return FiniteFieldElement{Value: t, Field: f.Field}
}
func (f FiniteFieldElement) Sub(other FiniteFieldElement) FiniteFieldElement {
	if f.Field.Prime.Cmp(other.Field.Prime) != 0 {
		panic("Cannot sub elements from different fields")
	}
	t := new(big.Int).Sub(f.Value, other.Value)
	t.Mod(t, f.Field.Prime)
	return FiniteFieldElement{Value: t, Field: f.Field}
}

/*
func (f FiniteFieldElement) Mul(other FiniteFieldElement) FiniteFieldElement {
	if f.Field.Prime.Cmp(other.Field.Prime) != 0 {
		panic("Cannot mul elements from different fields")
	}
	t := new(big.Int).Mul(f.Value, other.Value)
	t.Mod(t, f.Field.Prime)
	return FiniteFieldElement{Value: t, Field: f.Field}
}*/
func (f FiniteFieldElement) Mul(other FiniteFieldElement) FiniteFieldElement {
	// Check if either element is invalid
	if f.Value == nil || other.Value == nil {
		panic("Cannot multiply nil FiniteFieldElement values")
	}

	if f.Field.Prime == nil || other.Field.Prime == nil {
		panic("Cannot multiply elements with nil Field")
	}

	// Check if the elements belong to the same field
	if f.Field.Prime.Cmp(other.Field.Prime) != 0 {
		panic("Cannot multiply elements from different fields")
	}

	// Perform multiplication
	t := new(big.Int).Mul(f.Value, other.Value)
	t.Mod(t, f.Field.Prime)

	return FiniteFieldElement{Value: t, Field: f.Field}
}

func (f FiniteFieldElement) Inverse() FiniteFieldElement {
	t := new(big.Int).ModInverse(f.Value, f.Field.Prime)
	if t == nil {
		panic("Element has no modular inverse")
	}
	return FiniteFieldElement{Value: t, Field: f.Field}
}
func (f FiniteFieldElement) Division(x FiniteFieldElement) FiniteFieldElement {
	if f.Field.Prime.Cmp(x.Field.Prime) != 0 {
		panic("Cannot divide elements from different fields")
	}
	t := x.Inverse()
	s := f.Mul(t)
	return FiniteFieldElement{Value: s.Value, Field: f.Field}
}
func (f FiniteFieldElement) IsEqual(x FiniteFieldElement) bool {
	return f.Value.Cmp(x.Value) == 0
}
func (f FiniteFieldElement) Negate() FiniteFieldElement {
	t := new(big.Int).Neg(f.Value)
	t.Mod(t, f.Field.Prime)
	return FiniteFieldElement{Value: t, Field: f.Field}
}
func (f FiniteFieldElement) IsZero() bool {
	return f.Value.Cmp(big.NewInt(0)) == 0
}
func (f FiniteFieldElement) Exp(q FiniteFieldElement) FiniteFieldElement {
	if f.Field != q.Field {
		panic("different field exp")
	}
	t := new(big.Int).Exp(f.Value, q.Value, f.Field.Prime)
	return FiniteFieldElement{Value: t, Field: f.Field}
}
func BytesToField(chunks [][]byte) []FiniteFieldElement {
	var result []FiniteFieldElement
	for _, b := range chunks {
		bigint := new(big.Int).SetBytes(b)
		result = append(result, DefaultField.NewFieldElement(bigint))
	}
	return result
}
