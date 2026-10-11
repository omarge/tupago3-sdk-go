package client_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/omarge/tupago3-sdk-go/client"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
)

// expectField asserts a message field's number and protoreflect kind.
func expectField(t *testing.T, msg proto.Message, name string, num protoreflect.FieldNumber, kind protoreflect.Kind) {
	t.Helper()
	d := msg.ProtoReflect().Descriptor()
	fd := d.Fields().ByName(protoreflect.Name(name))
	require.NotNilf(t, fd, "field %s missing on %s", name, d.FullName())
	assert.Equalf(t, num, fd.Number(), "field %s number", name)
	assert.Equalf(t, kind, fd.Kind(), "field %s kind", name)
}

// --- Point 2/3: field numbers and scalar types are immutable / exact. ---
func TestContractFieldNumbers(t *testing.T) {
	expectField(t, &v1.GetClienteRequest{}, "id", 1, protoreflect.Int64Kind)
	expectField(t, &v1.GetCatalogoRequest{}, "clave_institucion", 1, protoreflect.StringKind)
	expectField(t, &v1.GetStatusRequest{}, "idc", 1, protoreflect.StringKind)
	expectField(t, &v1.GetStatusRequest{}, "id_cuenta", 2, protoreflect.Int64Kind)
	expectField(t, &v1.CreateQrRequest{}, "id_cuenta", 1, protoreflect.Int64Kind)
	expectField(t, &v1.CreateQrRequest{}, "monto", 2, protoreflect.DoubleKind)
	expectField(t, &v1.CreateQrRequest{}, "concepto", 3, protoreflect.StringKind)
	expectField(t, &v1.CreateQrRequest{}, "referencia_numerica", 4, protoreflect.Int32Kind)
	expectField(t, &v1.CreateQrRequest{}, "tipo_pago", 7, protoreflect.Int32Kind)
	expectField(t, &v1.CreateQrRequest{}, "vigencia", 8, protoreflect.Int32Kind)
	expectField(t, &v1.CreateQrRequest{}, "idempotency_key", 9, protoreflect.StringKind)
	expectField(t, &v1.CreateTelefonicoRequest{}, "key", 1, protoreflect.StringKind)
	expectField(t, &v1.CreateTelefonicoRequest{}, "monto", 2, protoreflect.DoubleKind)
	expectField(t, &v1.CreateTelefonicoRequest{}, "idempotency_key", 7, protoreflect.StringKind)
	expectField(t, &v1.ClientePerfil{}, "cliente", 1, protoreflect.MessageKind)
	expectField(t, &v1.Cliente{}, "id", 1, protoreflect.Int64Kind)
	expectField(t, &v1.CatalogoInstitucion{}, "clave_institucion", 2, protoreflect.StringKind)
	expectField(t, &v1.JsonResponse{}, "json", 1, protoreflect.StringKind)
}

// --- Point 3: int64 serialization is exact (no precision loss). ---
func TestInt64ExactSerialization(t *testing.T) {
	cases := []int64{0, 1, -1, 9223372036854775807, -9223372036854775808, 123456789012345}
	for _, v := range cases {
		req := &v1.GetClienteRequest{Id: v}
		b, err := proto.Marshal(req)
		require.NoError(t, err)
		var out v1.GetClienteRequest
		require.NoError(t, proto.Unmarshal(b, &out))
		assert.Equalf(t, v, out.Id, "int64 round-trip must be exact for %d", v)
	}
	// double monto round-trips deterministically for the same value
	qr := &v1.CreateQrRequest{IdCuenta: 1, Monto: 123456.789, IdempotencyKey: "k"}
	bb, err := proto.Marshal(qr)
	require.NoError(t, err)
	var qr2 v1.CreateQrRequest
	require.NoError(t, proto.Unmarshal(bb, &qr2))
	assert.Equal(t, qr.Monto, qr2.Monto)
}

// --- Point 3: monto range validation rejects invalid inputs. ---
func TestMontoValidation(t *testing.T) {
	assert.NoError(t, client.ValidateMonto(0.01))
	assert.NoError(t, client.ValidateMonto(1000))
	assert.Error(t, client.ValidateMonto(0))
	assert.Error(t, client.ValidateMonto(-1))
	assert.Error(t, client.ValidateMonto(math.NaN()))
	assert.Error(t, client.ValidateMonto(math.Inf(1)))
	assert.Error(t, client.ValidateMonto(client.MaxMonto+1))
}

// --- Point 4: JsonResponse.json passes through unchanged at the wire level. ---
func TestJsonResponseWirePassthrough(t *testing.T) {
	payload := `{"banxico":{"estado":"PAGADO","folio":"X-9"}}`
	jr := &v1.JsonResponse{Json: payload}
	b, err := proto.Marshal(jr)
	require.NoError(t, err)
	var got v1.JsonResponse
	require.NoError(t, proto.Unmarshal(b, &got))
	assert.Equal(t, payload, got.Json)
}
