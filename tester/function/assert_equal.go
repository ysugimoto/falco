package function

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Assert_equal_lookup_Name = "assert"

func Assert_equal_lookup_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Assert_equal_lookup_Name, 2, 3, args)
	}
	if len(args) == 3 {
		if args[2].Type() != value.StringType {
			return errors.TypeMismatch(Assert_equal_lookup_Name, 3, value.StringType, args[2].Type())
		}
	}
	return nil
}

func Assert_equal(ctx *context.Context, args ...value.Value) (value.Value, error) {
	if err := Assert_equal_lookup_Validate(args); err != nil {
		return nil, errors.NewTestingError(err.Error())
	}

	// Check custom message
	var message string
	if len(args) == 3 {
		message = value.Unwrap[*value.String](args[2]).Value
	}

	// assert.equal compares fuzzy typing
	expect, actual := args[0], args[1]
	switch expect.Type() {
	case value.NullType:
		return assert(value.NullType, actual.Type(), message)
	case value.IntegerType:
		lv := value.Unwrap[*value.Integer](expect)
		switch actual.Type() {
		case value.StringType: // INTEGER vs STRING
			rv := value.Unwrap[*value.String](actual)
			return assert(fmt.Sprint(lv.Value), rv.Value, message)
		case value.IntegerType: // INTEGER vs INTEGER
			rv := value.Unwrap[*value.Integer](actual)
			return assert(lv.Value, rv.Value, message)
		case value.FloatType: // INTEGER vs FLOAT
			rv := value.Unwrap[*value.Float](actual)
			return assert(float64(lv.Value), rv.Value, message)
		case value.RTimeType: // INTEGER vs RTIME
			rv := value.Unwrap[*value.RTime](actual)
			return assert(lv.Value, int64(rv.Value), message)
		default: // cannot comperable
			return nil, errors.NewTestingError(
				"Could not assert for %s type against INTEGER type",
				actual.Type(),
			)
		}
	case value.FloatType:
		lv := value.Unwrap[*value.Float](expect)
		switch actual.Type() {
		case value.StringType: // FLOAT vs STRING
			rv := value.Unwrap[*value.String](actual)
			return assert(strconv.FormatFloat(lv.Value, 'f', 3, 64), rv.Value, message)
		case value.IntegerType: // FLOAT vs INTEGER
			rv := value.Unwrap[*value.Integer](actual)
			return assert(lv.Value, float64(rv.Value), message)
		case value.FloatType: // FLOAT vs FLOAT
			rv := value.Unwrap[*value.Float](actual)
			return assert(lv.Value, rv.Value, message)
		case value.RTimeType: // FLOAT vs RTIME
			rv := value.Unwrap[*value.RTime](actual)
			return assert(lv.Value, float64(rv.Value), message)
		default: // cannot comperable
			return nil, errors.NewTestingError(
				"Could not assert for %s type against FLOAT type",
				actual.Type(),
			)
		}
	case value.StringType:
		lv := value.Unwrap[*value.String](expect)
		switch actual.Type() {
		case value.StringType: // STRING vs STRING
			rv := value.Unwrap[*value.String](actual)
			return assert(lv.Value, rv.Value, message)
		case value.IntegerType: // STRING vs INTEGER
			rv := value.Unwrap[*value.Integer](actual)
			return assert(lv.Value, fmt.Sprint(rv.Value), message)
		case value.FloatType: // STRING vs FLOAT
			rv := value.Unwrap[*value.Float](actual)
			return assert(lv.Value, strconv.FormatFloat(rv.Value, 'f', 3, 64), message)
		case value.BooleanType: // STRING vs BOOL
			rv := value.Unwrap[*value.Boolean](actual)
			rvv := "0"
			if rv.Value {
				rvv = "1"
			}
			return assert(lv.Value, rvv, message)
		case value.RTimeType: // STRING vs RTIME
			rv := value.Unwrap[*value.RTime](actual)
			return assert(lv.Value, rv.String(), message)
		case value.TimeType: // STRING vs TIME
			rv := value.Unwrap[*value.Time](actual)
			return assert(lv.Value, rv.String(), message)
		case value.BackendType: // STRING vs BACKEND
			rv := value.Unwrap[*value.Backend](actual)
			return assert(lv.Value, rv.Value.Name.Value, message)
		case value.AclType: // STRING vs ACL
			rv := value.Unwrap[*value.Acl](actual)
			return assert(lv.Value, rv.Value.Name.Value, message)
		case value.IpType: // STRING vs IP
			rv := value.Unwrap[*value.IP](actual)
			return assert(lv.Value, rv.Value.String(), message)
		default:
			return nil, errors.NewTestingError(
				"Could not assert for %s type against STRING type",
				actual.Type(),
			)
		}
	case value.BooleanType:
		lv := value.Unwrap[*value.Boolean](expect)
		switch actual.Type() {
		case value.BooleanType: // BOOL vs BOOL
			rv := value.Unwrap[*value.Boolean](actual)
			return assert(lv.Value, rv.Value, message)
		case value.StringType: // BOOL vs STRING
			rv := value.Unwrap[*value.String](actual)
			switch rv.Value {
			case "1":
				return assert(lv.Value, true, message)
			case "0":
				return assert(lv.Value, false, message)
			default:
				if message != "" {
					return &value.Boolean{}, errors.NewAssertionError(message)
				}
				return &value.Boolean{}, errors.NewAssertionError(
					"Assertion error: expect=%v, actual=%s", lv.Value, rv.Value,
				)
			}
		default:
			return nil, errors.NewTestingError(
				"Could not assert for %s type against BOOLEAN type",
				actual.Type(),
			)
		}
	case value.RTimeType:
		lv := value.Unwrap[*value.RTime](expect)
		switch actual.Type() {
		case value.StringType: // RTIME vs STRING
			rv := value.Unwrap[*value.String](actual)
			var val time.Duration
			var err error
			switch {
			case strings.HasSuffix(rv.Value, "d"):
				num := strings.TrimSuffix(rv.Value, "d")
				val, err = time.ParseDuration(num + "h")
				if err != nil {
					return nil, errors.NewTestingError("Failed to convert RTime from duration: %s", rv.Value)
				}
				val *= 24
			case strings.HasSuffix(rv.Value, "y"):
				num := strings.TrimSuffix(rv.Value, "y")
				val, err = time.ParseDuration(num + "h")
				if err != nil {
					return nil, errors.NewTestingError("Failed to convert RTime from duration: %s", rv.Value)
				}
				val *= 24 * 365
			default:
				val, err = time.ParseDuration(rv.Value)
				if err != nil {
					return nil, errors.NewTestingError("Failed to convert RTime from duration: %s", rv.Value)
				}
			}
			return assert(int64(lv.Value), int64(val), message)
		case value.IntegerType: // RTIME vs INTEGER
			rv := value.Unwrap[*value.Integer](actual)
			// Compare with second
			return assert(int64(lv.Value.Seconds()), rv.Value, message)
		case value.FloatType: // RTIME vs FLOAT
			rv := value.Unwrap[*value.Float](actual)
			return assert(lv.Value.Seconds(), rv.Value, message)
		case value.RTimeType: // RTIME vs RTIME
			rv := value.Unwrap[*value.RTime](actual)
			return assert(int64(lv.Value), int64(rv.Value), message)
		default:
			return nil, errors.NewTestingError(
				"Could not assert for %s type against RTIME type",
				actual.Type(),
			)
		}
	case value.TimeType:
		lv := value.Unwrap[*value.Time](expect)
		switch actual.Type() {
		case value.StringType: // TIME vs STRING
			rv := value.Unwrap[*value.String](actual)
			return assert(lv.String(), rv.Value, message)
		case value.TimeType: // TIME vs TIME
			rv := value.Unwrap[*value.Time](actual)
			return assert(lv.String(), rv.String(), message)
		default:
		}
	case value.IpType:
		lv := value.Unwrap[*value.IP](expect)
		switch actual.Type() {
		case value.StringType: // IP vs STRING
			rv := value.Unwrap[*value.String](actual)
			return assert(lv.Value.String(), rv.Value, message)
		case value.IpType: // IP vs IP
			rv := value.Unwrap[*value.IP](actual)
			return assert(lv.Value.String(), rv.Value.String(), message)
		default:
		}
	case value.BackendType:
		lv := value.Unwrap[*value.Backend](expect)
		switch actual.Type() {
		case value.BackendType: // BACKEND vs BACKEND
			rv := value.Unwrap[*value.Backend](actual)
			return assert(lv.Value.Name.Value, rv.Value.Name.Value, message)
		case value.StringType: // BACKEND vs STRING
			rv := value.Unwrap[*value.String](actual)
			return assert(lv.Value.Name.Value, rv.Value, message)
		default:
			return nil, errors.NewTestingError(
				"Could not assert for %s type against BACKEND type",
				actual.Type(),
			)
		}
	case value.AclType:
		lv := value.Unwrap[*value.Acl](expect)
		switch actual.Type() {
		case value.AclType: // ACL vs ACL
			rv := value.Unwrap[*value.Acl](actual)
			return assert(lv.Value.Name.Value, rv.Value.Name.Value, message)
		case value.StringType: // ACL vs STRING
			rv := value.Unwrap[*value.String](actual)
			return assert(lv.Value.Name.Value, rv.Value, message)
		default:
			return nil, errors.NewTestingError(
				"Could not assert for %s type against ACL type",
				actual.Type(),
			)
		}
	}
	return nil, errors.NewTestingError(
		"Assertion type mismatch, expect %s, actual %s",
		expect.Type(),
		actual.Type(),
	)
}
