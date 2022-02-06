package gldap

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControlPaging(t *testing.T) {
	runControlTest(t,
		NewControlPaging(0),
		withTestType(ControlTypePaging),
		withTestToString("Control Type: Paging (\"1.2.840.113556.1.4.319\")  Criticality: false  PagingSize: 0  Cookie: \"\""),
	)
	runControlTest(t, NewControlPaging(100))
}

func TestControlManageDsaIT(t *testing.T) {
	runControlTest(t,
		NewControlManageDsaIT(true),
		withTestType(ControlTypeManageDsaIT),
		withTestToString("Control Type: Manage DSA IT (\"2.16.840.1.113730.3.4.2\")  Criticality: true"),
	)
	runControlTest(t, NewControlManageDsaIT(false))
}

func TestControlMicrosoftNotification(t *testing.T) {
	runControlTest(t,
		NewControlMicrosoftNotification(),
		withTestType(ControlTypeMicrosoftNotification),
		withTestToString("Control Type: Change Notification - Microsoft (\"1.2.840.113556.1.4.528\")"),
	)
}

func TestControlMicrosoftShowDeleted(t *testing.T) {
	runControlTest(t,
		NewControlMicrosoftShowDeleted(),
		withTestType(ControlTypeMicrosoftShowDeleted),
		withTestToString("Control Type: Show Deleted Objects - Microsoft (\"1.2.840.113556.1.4.417\")"),
	)
}

func TestControlMicrosoftServerLinkTTL(t *testing.T) {
	runControlTest(t,
		NewControlMicrosoftServerLinkTTL(),
		withTestType(ControlTypeMicrosoftServerLinkTTL),
		withTestToString("Control Type: Return TTL-DNs for link values with associated expiry times - Microsoft (\"1.2.840.113556.1.4.2309\")"),
	)
}

func TestControlString(t *testing.T) {
	runControlTest(t,
		NewControlString("x", true, "y"),
		withTestType("x"),
		withTestToString("Control Type:  (\"x\")  Criticality: true  Control Value: y"),
	)
	runControlTest(t, NewControlString("x", true, ""))
	runControlTest(t, NewControlString("x", false, "y"))
	runControlTest(t, NewControlString("x", false, ""))
}

func runControlTest(t *testing.T, originalControl Control, opt ...Option) {
	header := ""
	if callerpc, _, line, ok := runtime.Caller(1); ok {
		if caller := runtime.FuncForPC(callerpc); caller != nil {
			header = fmt.Sprintf("%s:%d: ", caller.Name(), line)
		}
	}

	encodedPacket := originalControl.Encode()
	encodedBytes := encodedPacket.Bytes()

	// Decode directly from the encoded packet (ensures Value is correct)
	fromPacket, err := decodeControl(encodedPacket)
	if err != nil {
		t.Errorf("%s: decoding encoded bytes control failed: %s", header, err)
	}
	if !bytes.Equal(encodedBytes, fromPacket.Encode().Bytes()) {
		t.Errorf("%s: round-trip from encoded packet failed", header)
	}
	if reflect.TypeOf(originalControl) != reflect.TypeOf(fromPacket) {
		t.Errorf("%s: got different type decoding from encoded packet: %T vs %T", header, fromPacket, originalControl)
	}

	// Decode from the wire bytes (ensures ber-encoding is correct)
	pkt, err := ber.DecodePacketErr(encodedBytes)
	if err != nil {
		t.Errorf("%s: decoding encoded bytes failed: %s", header, err)
	}
	fromBytes, err := decodeControl(pkt)
	if err != nil {
		t.Errorf("%s: decoding control failed: %s", header, err)
	}
	if !bytes.Equal(encodedBytes, fromBytes.Encode().Bytes()) {
		t.Errorf("%s: round-trip from encoded bytes failed", header)
	}
	if reflect.TypeOf(originalControl) != reflect.TypeOf(fromPacket) {
		t.Errorf("%s: got different type decoding from encoded bytes: %T vs %T", header, fromBytes, originalControl)
	}
	opts := getControlOpts(opt...)
	if opts.withTestType != "" {
		assert.Equal(t, opts.withTestType, fromPacket.GetControlType())
	}
	if opts.withTestToString != "" {
		assert.Equal(t, opts.withTestToString, fromPacket.String())
	}
}

func TestDescribeControlManageDsaIT(t *testing.T) {
	runAddControlDescriptions(t, NewControlManageDsaIT(false), "Control Type (Manage DSA IT)")
	runAddControlDescriptions(t, NewControlManageDsaIT(true), "Control Type (Manage DSA IT)", "Criticality")
}

func TestDescribeControlPaging(t *testing.T) {
	runAddControlDescriptions(t, NewControlPaging(100), "Control Type (Paging)", "Control Value (Paging)")
	runAddControlDescriptions(t, NewControlPaging(0), "Control Type (Paging)", "Control Value (Paging)")
}

func TestDescribeControlMicrosoftNotification(t *testing.T) {
	runAddControlDescriptions(t, NewControlMicrosoftNotification(), "Control Type (Change Notification - Microsoft)")
}

func TestDescribeControlMicrosoftShowDeleted(t *testing.T) {
	runAddControlDescriptions(t, NewControlMicrosoftShowDeleted(), "Control Type (Show Deleted Objects - Microsoft)")
}

func TestDescribeControlMicrosoftServerLinkTTL(t *testing.T) {
	runAddControlDescriptions(t, NewControlMicrosoftServerLinkTTL(), "Control Type (Return TTL-DNs for link values with associated expiry times - Microsoft)")
}

func TestDescribeControlString(t *testing.T) {
	runAddControlDescriptions(t, NewControlString("x", true, "y"), "Control Type ()", "Criticality", "Control Value")
	runAddControlDescriptions(t, NewControlString("x", true, ""), "Control Type ()", "Criticality")
	runAddControlDescriptions(t, NewControlString("x", false, "y"), "Control Type ()", "Control Value")
	runAddControlDescriptions(t, NewControlString("x", false, ""), "Control Type ()")
}

func runAddControlDescriptions(t *testing.T, originalControl Control, childDescriptions ...string) {
	header := ""
	if callerpc, _, line, ok := runtime.Caller(1); ok {
		if caller := runtime.FuncForPC(callerpc); caller != nil {
			header = fmt.Sprintf("%s:%d: ", caller.Name(), line)
		}
	}

	encodedControls := encodeControls([]Control{originalControl})
	addControlDescriptions(encodedControls)
	encodedPacket := encodedControls.Children[0]
	if len(encodedPacket.Children) != len(childDescriptions) {
		t.Errorf("%sinvalid number of children: %d != %d", header, len(encodedPacket.Children), len(childDescriptions))
	}
	for i, desc := range childDescriptions {
		if encodedPacket.Children[i].Description != desc {
			t.Errorf("%s: description not as expected: %s != %s", header, encodedPacket.Children[i].Description, desc)
		}
	}
}

func TestDecodeControl(t *testing.T) {
	type args struct {
		packet *ber.Packet
	}

	tests := []struct {
		name    string
		args    args
		want    Control
		wantErr bool
	}{
		{
			name: "timeBeforeExpiration", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x29, 0x30, 0x27, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0xa, 0x30, 0x8, 0xa0, 0x6, 0x80, 0x4, 0x7f, 0xff, 0xf6, 0x5c})},
			want: &ControlBeheraPasswordPolicy{expire: 2147481180, grace: -1, error: -1, errorString: ""}, wantErr: false,
		},
		{
			name: "graceAuthNsRemaining", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x26, 0x30, 0x24, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x7, 0x30, 0x5, 0xa0, 0x3, 0x81, 0x1, 0x11})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: 17, error: -1, errorString: ""}, wantErr: false,
		},
		{
			name: "passwordExpired", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x0})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 0, errorString: "Password expired"}, wantErr: false,
		},
		{
			name: "accountLocked", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x1})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 1, errorString: "Account locked"}, wantErr: false,
		},
		{
			name: "passwordModNotAllowed", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x3})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 3, errorString: "Policy prevents password modification"}, wantErr: false,
		},
		{
			name: "mustSupplyOldPassword", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x4})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 4, errorString: "Policy requires old password in order to change password"}, wantErr: false,
		},
		{
			name: "insufficientPasswordQuality", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x5})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 5, errorString: "Password fails quality checks"}, wantErr: false,
		},
		{
			name: "passwordTooShort", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x6})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 6, errorString: "Password is too short for policy"}, wantErr: false,
		},
		{
			name: "passwordTooYoung", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x7})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 7, errorString: "Password has been changed too recently"}, wantErr: false,
		},
		{
			name: "passwordInHistory", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x8})},
			want: &ControlBeheraPasswordPolicy{expire: -1, grace: -1, error: 8, errorString: "New password is in list of old passwords"}, wantErr: false,
		},
	}
	for i := range tests {
		err := addControlDescriptions(tests[i].args.packet)
		if err != nil {
			t.Fatal(err)
		}
		tests[i].args.packet = tests[i].args.packet.Children[0]
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if strings.ToLower(os.Getenv("DEBUG")) == "true" {
				fmt.Println("****************************")
				fmt.Println(tt.name)
				p := packet{Packet: tt.args.packet}
				p.debug()
			}
			got, err := decodeControl(tt.args.packet)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeControl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeControl() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestControl_Encode(t *testing.T) {
	tests := []struct {
		name    string
		control Control
		opts    []Option
		want    Control
	}{
		{
			name: "withGraceAuthNsRemaining",
			control: func() Control {
				c, err := NewControlBeheraPasswordPolicy(WithGraceAuthNsRemaining(17))
				require.NoError(t, err)
				return c
			}(),
			want: &ControlBeheraPasswordPolicy{
				expire:      -1,
				grace:       17,
				error:       -1,
				errorString: "",
			},
		},
		{
			name: "timeBeforeExpiration",
			control: func() Control {
				c, err := NewControlBeheraPasswordPolicy(WithSecondsBeforeExpiration(2147481180))
				require.NoError(t, err)
				return c
			}(),
			want: &ControlBeheraPasswordPolicy{
				expire:      2147481180,
				grace:       -1,
				error:       -1,
				errorString: "",
			},
		},
		{
			name: "BeheraPasswordExpired",
			control: func() Control {
				c, err := NewControlBeheraPasswordPolicy(WithErrorCode(BeheraPasswordExpired))
				require.NoError(t, err)
				return c
			}(),
			want: &ControlBeheraPasswordPolicy{
				expire:      -1,
				grace:       -1,
				error:       BeheraPasswordExpired,
				errorString: BeheraPasswordPolicyErrorMap[BeheraPasswordExpired],
			},
		},
		{
			name: "BeheraAccountLocked",
			control: func() Control {
				c, err := NewControlBeheraPasswordPolicy(WithErrorCode(BeheraAccountLocked))
				require.NoError(t, err)
				return c
			}(),
			want: &ControlBeheraPasswordPolicy{
				expire:      -1,
				grace:       -1,
				error:       BeheraAccountLocked,
				errorString: BeheraPasswordPolicyErrorMap[BeheraAccountLocked],
			},
		},
		{
			name:    "ControlVChuPasswordMustChange",
			control: &ControlVChuPasswordMustChange{MustChange: true},
			opts:    []Option{withTestType(ControlTypeVChuPasswordMustChange), withTestToString(`Control Type:  ("2.16.840.1.113730.3.4.4")  Criticality: false  MustChange: true`)},
			want:    &ControlVChuPasswordMustChange{MustChange: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if strings.ToLower(os.Getenv("DEBUG")) == "true" {
				raw := tc.control.Encode()
				p := packet{Packet: raw}
				p.debug()
			}
			runControlTest(t, tc.control, tc.opts...)
		})
	}
}

func Test_NewControlBeheraPassword(t *testing.T) {
	tests := []struct {
		name            string
		opts            []Option
		want            Control
		wantString      string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "grace-and-expire",
			opts:            []Option{WithGraceAuthNsRemaining(1), WithSecondsBeforeExpiration(1)},
			wantErr:         true,
			wantErrContains: "cannot have both grace and expire",
		},
		{
			name:            "grace-and-error-code",
			opts:            []Option{WithGraceAuthNsRemaining(1), WithErrorCode(1)},
			wantErr:         true,
			wantErrContains: "cannot have both grace and error",
		},
		{
			name:            "expire-and-error-code",
			opts:            []Option{WithSecondsBeforeExpiration(1), WithErrorCode(1)},
			wantErr:         true,
			wantErrContains: "cannot have both expire and error",
		},
		{
			name:            "invalid-error-code",
			opts:            []Option{WithErrorCode(9)},
			wantErr:         true,
			wantErrContains: "9 is not a valid behera policy error code (must be between 0-8",
		},
		{
			name: "valid-grace",
			opts: []Option{WithGraceAuthNsRemaining(1)},
			want: &ControlBeheraPasswordPolicy{
				grace:       1,
				expire:      -1,
				error:       -1,
				errorString: "",
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: 1  Error: -1, ErrorString: `,
		},
		{
			name: "valid-expire",
			opts: []Option{WithSecondsBeforeExpiration(1)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      1,
				error:       -1,
				errorString: "",
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: 1  Grace: -1  Error: -1, ErrorString: `,
		},
		{
			name: "BeheraPasswordExpired",
			opts: []Option{WithErrorCode(BeheraPasswordExpired)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraPasswordExpired,
				errorString: BeheraPasswordPolicyErrorMap[BeheraPasswordExpired],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 0, ErrorString: Password expired`,
		},
		{
			name: "BeheraAccountLocked",
			opts: []Option{WithErrorCode(BeheraAccountLocked)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraAccountLocked,
				errorString: BeheraPasswordPolicyErrorMap[BeheraAccountLocked],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 1, ErrorString: Account locked`,
		},
		{
			name: "BeheraChangeAfterReset",
			opts: []Option{WithErrorCode(BeheraChangeAfterReset)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraChangeAfterReset,
				errorString: BeheraPasswordPolicyErrorMap[BeheraChangeAfterReset],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 2, ErrorString: Password must be changed`,
		},
		{
			name: "BeheraPasswordModNotAllowed",
			opts: []Option{WithErrorCode(BeheraPasswordModNotAllowed)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraPasswordModNotAllowed,
				errorString: BeheraPasswordPolicyErrorMap[BeheraPasswordModNotAllowed],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 3, ErrorString: Policy prevents password modification`,
		},
		{
			name: "BeheraMustSupplyOldPassword",
			opts: []Option{WithErrorCode(BeheraMustSupplyOldPassword)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraMustSupplyOldPassword,
				errorString: BeheraPasswordPolicyErrorMap[BeheraMustSupplyOldPassword],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 4, ErrorString: Policy requires old password in order to change password`,
		},
		{
			name: "BeheraInsufficientPasswordQuality",
			opts: []Option{WithErrorCode(BeheraInsufficientPasswordQuality)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraInsufficientPasswordQuality,
				errorString: BeheraPasswordPolicyErrorMap[BeheraInsufficientPasswordQuality],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 5, ErrorString: Password fails quality checks`,
		},
		{
			name: "BeheraPasswordTooShort",
			opts: []Option{WithErrorCode(BeheraPasswordTooShort)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraPasswordTooShort,
				errorString: BeheraPasswordPolicyErrorMap[BeheraPasswordTooShort],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 6, ErrorString: Password is too short for policy`,
		},
		{
			name: "BeheraPasswordTooYoung",
			opts: []Option{WithErrorCode(BeheraPasswordTooYoung)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraPasswordTooYoung,
				errorString: BeheraPasswordPolicyErrorMap[BeheraPasswordTooYoung],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 7, ErrorString: Password has been changed too recently`,
		},
		{
			name: "BeheraPasswordInHistory",
			opts: []Option{WithErrorCode(BeheraPasswordInHistory)},
			want: &ControlBeheraPasswordPolicy{
				grace:       -1,
				expire:      -1,
				error:       BeheraPasswordInHistory,
				errorString: BeheraPasswordPolicyErrorMap[BeheraPasswordInHistory],
			},
			wantString: `Control Type: Password Policy - Behera Draft ("1.3.6.1.4.1.42.2.27.8.5.1")  Criticality: false  Expire: -1  Grace: -1  Error: 8, ErrorString: New password is in list of old passwords`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			c, err := NewControlBeheraPasswordPolicy(tc.opts...)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(c)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, c)
			if tc.wantString != "" {
				assert.Equal(tc.wantString, c.String())
			}
			assert.Equal(ControlTypeBeheraPasswordPolicy, c.GetControlType())
			assert.Equal(int(c.grace), c.Grace())
			assert.Equal(int(c.expire), c.Expire())
			code, codeString := c.ErrorCode()
			assert.Equal(int(c.error), code)
			assert.Equal(c.errorString, codeString)
		})
	}
}
