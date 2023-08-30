/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

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
