package services

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/roger-protocol/roger-server/internal/config"
	"github.com/roger-protocol/roger-server/internal/crypto"
	"github.com/roger-protocol/roger-server/internal/db"
)

var (
	ErrUnsupportedProvider = errors.New("unsupported provider")
)

type AuthService struct {
	config  *config.Config
	queries *db.Queries
}

func NewAuthService(q *db.Queries, cfg *config.Config) *AuthService {
	return &AuthService{config: cfg, queries: q}
}

type oauthState struct {
	ClientState         string `json:"cs"`
	CodeChallenge       string `json:"cc"`
	CodeChallengeMethod string `json:"ccm"`
	RedirectURI         string `json:"ru"`
	IssuedAt            string `json:"iat"`
}

func (s *AuthService) GetProviderRedirectURL(providerID string, codeChallenge string, codeChallengeMethod string, state string, clientRedirectUri string) (string, error) {
	providerCfg, ok := s.config.Auth.Providers[providerID]
	if !ok {
		return "", ErrUnsupportedProvider
	}

	providerUrl, err := url.Parse(providerCfg.AuthURL)
	if err != nil {
		return "", fmt.Errorf("inavlid auth_url for %v provider, %w", providerID, err)
	}

	stateData := oauthState{
		ClientState:         state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         clientRedirectUri,
		IssuedAt:            strconv.FormatInt(time.Now().Unix(), 10),
	}

	jsonState, err := json.Marshal(stateData)
	if err != nil {
		return "", fmt.Errorf("couldn't encode state: %w", err)
	}

	encryptedState, err := crypto.AESEncrypt(s.config.Server.DBEncryptionKey, jsonState)
	if err != nil {
		return "", fmt.Errorf("couldn't encrypt state data: %w", err)
	}

	redirectUri, err := url.JoinPath(s.config.Server.ServerURL, providerCfg.CallbackPath)
	if err != nil {
		return "", fmt.Errorf("couldn't create redirect uri: %w", err)
	}

	query := providerUrl.Query()
	query.Set("client_id", providerCfg.ClientID)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(providerCfg.Scopes, " "))
	query.Set("state", base64.RawURLEncoding.EncodeToString(encryptedState))
	query.Set("redirect_uri", redirectUri)

	providerUrl.RawQuery = query.Encode()

	return providerUrl.String(), nil
}
