package core

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

type LandingPage struct{}

func (l LandingPage) Routes(router EchoRouter) {
	router.Add("GET", "/", func(context echo.Context) error {
		const content = `
<html>
	<head>
		<title>Nuts Node</title>
	</head>
	<body>
		<h1>Your Nuts Node is running!</h1>
		<p>
			Warning: if you see this message, it means you haven't properly secured your environment for production usage.<br />
			See <a href="https://nuts-node.readthedocs.io/en/latest/pages/production-configuration.html" target="_blank">Configuring for Production</a> for more information on this topic.
		</p>
		<p>
			<a href="status/diagnostics">Node Diagnotics</a>
		</p>
	</body>
</html>
		`
		return context.HTML(http.StatusOK, content)
	})
}
