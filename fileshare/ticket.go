package main

// Tickets are minted by the bastion (POST /api/sessions/<id>/fileshare-ticket)
// and exchanged here for a short file-service session. They are the only thing
// the two processes share: this service never reads the bastion database and
// the bastion never reads the files.
//
// Format: base64url(JSON payload) "." hex(HMAC-SHA256(secret, base64url part))

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Ticket types: a drive session ticket (browser) or a purge order (bastion,
// when a fileshare resource is deleted). A ticket of one type is never
// accepted as the other.
const (
	ticketSession = ""
	ticketPurge   = "purge"
)

type ticketClaims struct {
	Version   int    `json:"v"`
	Type      string `json:"typ,omitempty"`
	User      string `json:"sub"`
	UserID    int    `json:"uid"`
	Resource  int    `json:"rid"`
	SessionID int    `json:"sid"`
	IssuedAt  int64  `json:"iat"`
	Expires   int64  `json:"exp"`
	// End of the bastion session (its max duration): the file session never
	// outlives it, whatever the renewals.
	SessionExpires int64  `json:"sexp"`
	Nonce          string `json:"jti"`
}

var (
	errTicketMalformed = errors.New("malformed ticket")
	errTicketSignature = errors.New("invalid ticket signature")
	errTicketExpired   = errors.New("ticket expired")
	errTicketReplayed  = errors.New("ticket already used")
)

// Allowed clock drift between the bastion and this service.
const ticketClockSkew = 30 * time.Second

func signTicket(secret []byte, claims ticketClaims) (string, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return body + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

func verifyTicket(secret []byte, ticket string, now time.Time) (ticketClaims, error) {
	claims, err := decodeSigned(secret, ticket)
	if err != nil {
		return claims, err
	}
	if claims.Version != 1 || claims.Type != ticketSession || claims.User == "" ||
		claims.Resource <= 0 || claims.SessionID <= 0 || claims.Nonce == "" {
		return claims, errTicketMalformed
	}
	if claims.IssuedAt > now.Add(ticketClockSkew).Unix() ||
		claims.Expires < now.Add(-ticketClockSkew).Unix() ||
		claims.SessionExpires < now.Unix() {
		return claims, errTicketExpired
	}
	return claims, nil
}

// decodeSigned checks the signature and decodes the claims, whatever the type.
func decodeSigned(secret []byte, ticket string) (ticketClaims, error) {
	var claims ticketClaims
	if len(ticket) > 4096 {
		return claims, errTicketMalformed
	}
	body, sig, ok := strings.Cut(ticket, ".")
	if !ok || body == "" || sig == "" {
		return claims, errTicketMalformed
	}
	given, err := hex.DecodeString(sig)
	if err != nil {
		return claims, errTicketMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	if !hmac.Equal(given, mac.Sum(nil)) {
		return claims, errTicketSignature
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return claims, errTicketMalformed
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return claims, errTicketMalformed
	}
	return claims, nil
}

// verifyPurge checks a purge order: same signature, type "purge".
func verifyPurge(secret []byte, ticket string, now time.Time) (ticketClaims, error) {
	claims, err := decodeSigned(secret, ticket)
	if err != nil {
		return claims, err
	}
	if claims.Version != 1 || claims.Type != ticketPurge || claims.User == "" ||
		claims.Resource <= 0 || claims.Nonce == "" {
		return claims, errTicketMalformed
	}
	if claims.IssuedAt > now.Add(ticketClockSkew).Unix() ||
		claims.Expires < now.Add(-ticketClockSkew).Unix() {
		return claims, errTicketExpired
	}
	return claims, nil
}

// replayGuard remembers the nonces of tickets already exchanged until they
// would have expired anyway, so a ticket works once.
type replayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayGuard() *replayGuard {
	return &replayGuard{seen: make(map[string]time.Time)}
}

func (g *replayGuard) use(nonce string, until time.Time, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, exp := range g.seen {
		if exp.Before(now) {
			delete(g.seen, key)
		}
	}
	if _, dup := g.seen[nonce]; dup {
		return false
	}
	g.seen[nonce] = until.Add(ticketClockSkew)
	return true
}
