package mfa

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libregraph/lico/identifier"
	"github.com/libregraph/lico/identifier/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	microstore "go-micro.dev/v4/store"
)

// fakeUser is a minimal backends.UserFromBackend.
type fakeUser struct{ id, username string }

func (u fakeUser) Subject() string               { return u.id }
func (u fakeUser) Username() string              { return u.username }
func (u fakeUser) BackendClaims() map[string]any { return nil }
func (u fakeUser) BackendScopes() []string       { return nil }
func (u fakeUser) RequiredScopes() []string      { return nil }

// fakeBackend knows the users alan and mary, both with the password "secret".
type fakeBackend struct {
	backends.Backend
	err               error
	destroyedSessions []string
}

func (b *fakeBackend) Logon(_ context.Context, _, username, password string) (success bool, userID, sessionRef *string, user backends.UserFromBackend, err error) {
	if b.err != nil {
		return false, nil, nil, nil, b.err
	}
	for _, u := range []User{alan, mary} {
		if u.Username == username && password == "secret" {
			id := u.ID
			session := "session-of-" + username
			return true, &id, &session, fakeUser{id: u.ID, username: u.Username}, nil
		}
	}
	return false, nil, nil, nil, nil
}

func (b *fakeBackend) DestroySession(_ context.Context, sessionRef *string) error {
	b.destroyedSessions = append(b.destroyedSessions, *sessionRef)
	return nil
}

// the Service is handed to the identifier as its second factor
var _ identifier.SecondFactor = (*Service)(nil)

func totp(code string) *identifier.SecondFactorResponse {
	return &identifier.SecondFactorResponse{Type: identifier.SecondFactorTypeTOTP, Value: []byte(code)}
}

func TestSecondFactorMethods(t *testing.T) {
	svc, c, _ := newTestService(t)
	enroll(t, svc, c, alan)

	methods, err := svc.SecondFactorMethods(context.Background(), alan.ID, alan.Username)
	require.NoError(t, err)
	assert.Equal(t, []identifier.SecondFactorMethod{{Type: identifier.SecondFactorTypeTOTP}}, methods)

	methods, err = svc.SecondFactorMethods(context.Background(), mary.ID, mary.Username)
	require.NoError(t, err)
	assert.Empty(t, methods, "users without a second factor need none")
}

func TestVerifySecondFactor(t *testing.T) {
	svc, c, _ := newTestService(t)
	secret, codes := enroll(t, svc, c, alan)
	ctx := context.Background()

	verify := func(user User, response *identifier.SecondFactorResponse) identifier.SecondFactorResult {
		t.Helper()
		result, err := svc.VerifySecondFactor(ctx, user.ID, user.Username, response)
		require.NoError(t, err)
		return result
	}

	t.Run("a response for a user without second factor is not valid", func(t *testing.T) {
		assert.Equal(t, identifier.SecondFactorInvalid, verify(mary, totp("123456")))
	})

	t.Run("an empty code is invalid", func(t *testing.T) {
		assert.Equal(t, identifier.SecondFactorInvalid, verify(alan, totp(" ")))
	})

	t.Run("other types and oversized values are invalid", func(t *testing.T) {
		code := codeFor(t, secret, c.now())
		assert.Equal(t, identifier.SecondFactorInvalid, verify(alan, &identifier.SecondFactorResponse{Type: "webauthn", Value: []byte(code)}))
		assert.Equal(t, identifier.SecondFactorInvalid, verify(alan, totp(code+strings.Repeat(" ", maxResponseLength))))
		assert.Equal(t, identifier.SecondFactorInvalid, verify(alan, nil))
	})

	t.Run("a wrong code is invalid", func(t *testing.T) {
		assert.Equal(t, identifier.SecondFactorInvalid, verify(alan, totp("000000")))
	})

	t.Run("the current code is valid once", func(t *testing.T) {
		code := codeFor(t, secret, c.now())
		assert.Equal(t, identifier.SecondFactorValid, verify(alan, totp(code)))
		assert.Equal(t, identifier.SecondFactorInvalid, verify(alan, totp(code)))
	})

	t.Run("a recovery code is valid", func(t *testing.T) {
		assert.Equal(t, identifier.SecondFactorValid, verify(alan, totp(codes[0])))
	})

	t.Run("too many wrong codes lock", func(t *testing.T) {
		for range maxFailedAttempts - 1 {
			assert.Equal(t, identifier.SecondFactorInvalid, verify(alan, totp("000000")))
		}
		assert.Equal(t, identifier.SecondFactorLocked, verify(alan, totp("000000")))
		assert.Equal(t, identifier.SecondFactorLocked, verify(alan, totp(codeFor(t, secret, c.now()))))
	})
}

// failingStore fails all reads, like a store that is not reachable.
type failingStore struct{ microstore.Store }

func (failingStore) Read(string, ...microstore.ReadOption) ([]*microstore.Record, error) {
	return nil, errors.New("store is down")
}

func TestSecondFactorFailsClosedWhenTheStoreIsDown(t *testing.T) {
	svc, _, st := newTestService(t)
	svc.store = failingStore{Store: st}

	// mary has no second factor, but that cannot be known without the store
	_, err := svc.SecondFactorMethods(context.Background(), mary.ID, mary.Username)
	assert.Error(t, err)
	result, err := svc.VerifySecondFactor(context.Background(), mary.ID, mary.Username, totp("123456"))
	assert.Error(t, err)
	assert.NotEqual(t, identifier.SecondFactorValid, result)
}

func TestVerifyPassword(t *testing.T) {
	svc, _, _ := newTestService(t)

	_, err := svc.verifyPassword(context.Background(), alan, "secret")
	assert.Error(t, err, "needs a password verifier")

	inner := &fakeBackend{}
	svc.passwordVerifier = newPasswordVerifier(inner)

	ok, err := svc.verifyPassword(context.Background(), alan, "secret")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []string{"session-of-alan"}, inner.destroyedSessions)

	for _, password := range []string{"", "wrong"} {
		ok, err = svc.verifyPassword(context.Background(), alan, password)
		require.NoError(t, err)
		assert.False(t, ok)
	}

	// the password of another account with the same username does not count
	ok, err = svc.verifyPassword(context.Background(), User{ID: "another-id", Username: "alan"}, "secret")
	require.NoError(t, err)
	assert.False(t, ok)

	inner.err = errors.New("ldap is down")
	_, err = svc.verifyPassword(context.Background(), alan, "secret")
	assert.Error(t, err)
}
