package mfa

import (
	"context"
	"errors"

	"github.com/libregraph/lico/identifier"
	"github.com/libregraph/lico/identifier/backends"
)

// maxResponseLength is far more than any TOTP or recovery code; longer responses are
// refused without reading the store.
const maxResponseLength = 64

// SecondFactorMethods implements identifier.SecondFactor. The identifier calls it after
// the backend accepted the password of a user, so every username and password logon goes
// through it. Recovery codes are entered where the TOTP code goes. An error refuses the
// logon: without the store it is not known who needs a second factor.
func (s *Service) SecondFactorMethods(_ context.Context, userID, username string) ([]identifier.SecondFactorMethod, error) {
	status, err := s.Status(User{ID: userID, Username: username})
	if err != nil {
		return nil, err
	}
	if !status.Enabled {
		return nil, nil
	}
	return []identifier.SecondFactorMethod{{Type: identifier.SecondFactorTypeTOTP}}, nil
}

// VerifySecondFactor implements identifier.SecondFactor. Wrong codes count towards the
// lockout and a code is accepted only once (see VerifyLogin).
func (s *Service) VerifySecondFactor(_ context.Context, userID, username string, response *identifier.SecondFactorResponse) (identifier.SecondFactorResult, error) {
	if response == nil || response.Type != identifier.SecondFactorTypeTOTP || len(response.Value) > maxResponseLength {
		return identifier.SecondFactorInvalid, nil
	}
	result, err := s.VerifyLogin(User{ID: userID, Username: username}, string(response.Value))
	if err != nil {
		return identifier.SecondFactorInvalid, err
	}
	switch result {
	case LoginOK:
		return identifier.SecondFactorValid, nil
	case LoginLocked:
		return identifier.SecondFactorLocked, nil
	default:
		// Also for an empty code, and for a user without a second factor: the identifier
		// then asks for the methods, finds none and lets the password suffice.
		return identifier.SecondFactorInvalid, nil
	}
}

// passwordVerifier checks the password of a user without the second factor.
type passwordVerifier func(ctx context.Context, username, password string) (userID string, ok bool, err error)

// newPasswordVerifier checks passwords with the identifier backend directly, which never
// asks for a second factor.
func newPasswordVerifier(b backends.Backend) passwordVerifier {
	return func(ctx context.Context, username, password string) (string, bool, error) {
		ok, userID, sessionRef, _, err := b.Logon(ctx, "", username, password)
		if err != nil || !ok || userID == nil {
			return "", false, err
		}
		if sessionRef != nil {
			// only the password was checked, the session is not needed
			_ = b.DestroySession(ctx, sessionRef)
		}
		return *userID, true, nil
	}
}

// verifyPassword checks the password of the logged in user with the identifier backend.
func (s *Service) verifyPassword(ctx context.Context, user User, password string) (bool, error) {
	if s.passwordVerifier == nil {
		return false, errors.New("mfa: no password verifier, see NewHandler")
	}
	if password == "" {
		return false, nil
	}

	userID, ok, err := s.passwordVerifier(ctx, user.Username, password)
	if err != nil {
		return false, err
	}
	// make sure the password belongs to the logged in user
	return ok && userID == user.ID, nil
}
