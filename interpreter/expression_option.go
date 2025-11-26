package interpreter

type ExpressionOption struct {
	condition       bool
	isLocalVariable bool
}

func (eo *ExpressionOption) Condition() bool {
	// Need guard process due to option may be null
	if eo == nil {
		return false
	}
	return eo.condition
}

func (eo *ExpressionOption) IsLocalVariable() bool {
	// Need guard process due to option may be null
	if eo == nil {
		return false
	}
	return eo.isLocalVariable
}

func collectExpressionOption(opts ...expOption) *ExpressionOption {
	eo := &ExpressionOption{}
	for i := range opts {
		opts[i](eo)
	}
	return eo
}

type expOption func(eo *ExpressionOption)

func ConditionExpression() expOption {
	return func(eo *ExpressionOption) {
		eo.condition = true
	}
}

func LocalVariableExpression() expOption {
	return func(eo *ExpressionOption) {
		eo.isLocalVariable = true
	}
}
