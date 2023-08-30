package iam

import (
	"bytes"
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/url"
	"strings"
)

func (r *Wrapper) handleOpenID4VPDemoLanding(echoCtx echo.Context) error {
	requestURL := *echoCtx.Request().URL
	requestURL.Host = echoCtx.Request().Host
	requestURL.Scheme = "http"
	verifierID := requestURL.String()
	verifierID, _ = strings.CutSuffix(verifierID, "/openid4vp_demo")

	buf := new(bytes.Buffer)
	if err := r.templates.ExecuteTemplate(buf, "openid4vp_demo.html", struct {
		VerifierID string
		WalletID   string
	}{
		VerifierID: verifierID,
		WalletID:   verifierID,
	}); err != nil {
		return err
	}
	return echoCtx.HTML(http.StatusOK, buf.String())
}

func (r *Wrapper) handleOpenID4VPDemoSendRequest(echoCtx echo.Context) error {
	verifierID := echoCtx.FormValue("verifier_id")
	if verifierID == "" {
		return errors.New("missing verifier_id")
	}
	walletID := echoCtx.FormValue("wallet_id")
	if walletID == "" {
		return errors.New("missing wallet_id")
	}
	scope := echoCtx.FormValue("scope")
	if scope == "" {
		return errors.New("missing scope")
	}
	walletURL, _ := url.Parse(walletID)
	verifierURL, _ := url.Parse(verifierID)
	return r.sendPresentationRequest(
		echoCtx.Request().Context(), echoCtx.Response(), scope,
		*walletURL.JoinPath("openid4vp_completed"), *verifierURL, *walletURL,
	)
}
