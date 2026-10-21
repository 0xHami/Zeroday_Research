// Command ginextharness starts SEVERAL gin engines, each configured the way a real
// consuming application would be, to give stage-10 a live surface for the gin findings
// that are conditional (behind an Engine toggle) or realized only through an app pattern
// (a privileged bind struct, a JSONP endpoint, c.Scheme() in a link, c.Bind without a
// return, etc.). Every engine links the SAME local gin source as the default harness
// (go.mod `replace` -> /src/gin), so these exploits exercise gin's own code — the audit
// target — not third-party code. The app code here is deliberately the *minimal ordinary
// usage* that each finding says triggers it; the vulnerability lives in gin, not here.
//
// Ports (container -> host, within the CVEHUNT block 36274-36283):
//   8090 -> 36275  demo   (default config; extra routes: /account /scheme /jsonp /fmt /bindcontinue /save /ip)
//   8091 -> 36276  tp     (TrustedPlatform=X-CF-Connecting-IP + a CORRECT SetTrustedProxies)  VULN-003
//   8092 -> 36277  rawpath(UseRawPath=true, UnescapePathValues=true)                          VULN-008
//   8093 -> 36278  slash  (RemoveExtraSlash=true) + a literal-path "proxy" guard             VULN-009
//   8094 -> 36279  fixed  (RedirectFixedPath=true)                                            VULN-016
//   8095 -> 36280  mna    (HandleMethodNotAllowed=true)                                       VULN-017
//   8096 -> 36281  h2c    (UseH2C=true)                                                       VULN-006
//   8097 -> 36282  rparam (root-level /:tenant route)  VULN-001 full-host-control escalation
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// ---- VULN-004: a persistence/domain model with a privileged UNTAGGED field.
// The developer's form only offers "email"; IsAdmin/Role have no form tag, so gin's
// reflection binder (binding/form_mapping.go) binds them by Go field name from attacker
// input with no allowlist -> mass assignment.
type userModel struct {
	Email   string `form:"email" json:"email" binding:"required,email"`
	IsAdmin bool   // untagged -> bound from form/query key "IsAdmin"
	Role    string // untagged -> bound from form/query key "Role"
}

// ---- VULN-020: an order the handler "processes" after a Bind.
type orderReq struct {
	User   string `form:"user" binding:"required"`
	Amount int    `form:"amount" binding:"required"`
}

func demoEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	// VULN-004 — mass assignment. Bind straight into the privileged model (the common
	// "bind into the DB struct" pattern). Only "email" is an intended input.
	r.POST("/account", func(c *gin.Context) {
		var u userModel
		if err := c.ShouldBind(&u); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"email": u.Email, "IsAdmin": u.IsAdmin, "Role": u.Role})
	})

	// VULN-010 — Scheme() trusts X-Forwarded-Proto/-Protocol/-Ssl/-Url-Scheme with no
	// trusted-proxy gate. An app builds an absolute link (reset/canonical/OAuth) from it.
	r.GET("/scheme", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"scheme":    c.Scheme(),
			"built_url": c.Scheme() + "://" + c.Request.Host + c.Request.URL.Path,
		})
	})

	// VULN-011 — JSONP callback is not identifier-validated; it is written in code
	// position. Anything the endpoint returns is exfiltratable cross-origin via <script src>.
	r.GET("/jsonp", func(c *gin.Context) {
		c.JSONP(http.StatusOK, gin.H{"user": "bob", "secret": "s3cr3t-account-balance"})
	})

	// VULN-019 — String()/render.String passes the caller's string to fmt.Fprintf as the
	// FORMAT when any varargs are supplied. Here the dev thinks m is "the message" and
	// passes an internal secret as a value; a %-directive in m interprets it.
	r.GET("/fmt", func(c *gin.Context) {
		internalSecret := "INTERNAL-TOKEN-9f3a" // an unrelated value the dev passes as a vararg
		c.String(http.StatusOK, c.Query("m"), internalSecret)
	})

	// VULN-020 — Bind (not ShouldBind) commits 400 + Abort() on invalid input, but Abort()
	// does NOT stop the current handler. Code after c.Bind runs on zero/partial data.
	r.POST("/bindcontinue", func(c *gin.Context) {
		var o orderReq
		c.Bind(&o) // no `return` — the classic trap
		// A real app would now perform the side effect (DB write / charge), believing o is valid:
		log.Printf("[/bindcontinue] SIDE EFFECT RAN on user=%q amount=%d (bind may have failed)", o.User, o.Amount)
		c.String(http.StatusOK, "SIDE_EFFECT_RAN user=%q amount=%d", o.User, o.Amount)
	})

	// VULN-007 (write primitive) — app builds SaveUploadedFile's dst from a NON-filename
	// user input (a query param), which Go's multipart Base() does not neutralize.
	r.POST("/save", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		dst := filepath.Join("/app/uploads", c.Query("dst")) // dst tainted by ?dst=
		if err := c.SaveUploadedFile(file, dst); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"saved": dst})
	})

	// static so the write-primitive file can be read back
	r.Static("/static", "/app/public")

	return r
}

// VULN-003 — TrustedPlatform returned verbatim & first, defeating a CORRECT SetTrustedProxies.
func tpEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	// A correctly-locked-down proxy config: trust ONLY a specific proxy subnet that does
	// NOT include the docker gateway (the real peer). So a plain X-Forwarded-For is ignored.
	if err := r.SetTrustedProxies([]string{"192.0.2.0/24"}); err != nil {
		log.Printf("SetTrustedProxies: %v", err)
	}
	r.TrustedPlatform = "X-CF-Connecting-IP" // e.g. Cloudflare / Fly.io style
	r.GET("/ip", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"clientIP": c.ClientIP(), "remoteIP": c.RemoteIP()})
	})
	return r
}

// VULN-008 — UseRawPath: encoded separators (%2F, %2E%2E) survive as one :param segment,
// then gin decodes them into c.Param -> traversal at a file sink.
func rawPathEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.UseRawPath = true
	r.UnescapePathValues = true
	r.GET("/files/:name", func(c *gin.Context) {
		name := c.Param("name")
		// The app thinks :name is a single filename inside /app/public.
		c.File(filepath.Join("/app/public", name))
	})
	r.GET("/echo/:name", func(c *gin.Context) {
		c.String(http.StatusOK, "param=%q", c.Param("name"))
	})
	// A plain os.ReadFile sink (no http.ServeFile r.URL.Path ".." guard). The decoded
	// :param flows straight into the path -> traversal read.
	r.GET("/read/:name", func(c *gin.Context) {
		data, err := os.ReadFile(filepath.Join("/app/public", c.Param("name")))
		if err != nil {
			c.String(http.StatusNotFound, "err=%v", err)
			return
		}
		c.Data(http.StatusOK, "text/plain; charset=utf-8", data)
	})
	return r
}

// VULN-009 — RemoveExtraSlash collapses //, /./, /../ BEFORE routing, so a fronting guard
// that authorizes on the LITERAL path is bypassed. We simulate that guard as middleware
// that inspects the original c.Request.URL.Path (what a proxy/prefix check would see).
func slashEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.RemoveExtraSlash = true
	// "proxy/prefix authz": deny the protected path by its literal form.
	r.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/admin/panel" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"denied": "literal /admin/panel blocked"})
			return
		}
		c.Next()
	})
	r.GET("/admin/panel", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"admin": "panel reached", "seen_path": c.Request.URL.Path})
	})
	return r
}

// VULN-016 — RedirectFixedPath: case-insensitive auto-correct => 301 iff a route exists.
func fixedPathEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.RedirectFixedPath = true
	r.RedirectTrailingSlash = false // isolate the fixed-path behavior
	r.GET("/admin/secret", func(c *gin.Context) { c.String(http.StatusOK, "the real admin secret") })
	return r
}

// VULN-017 — HandleMethodNotAllowed: 405 + Allow header enumerates verbs/endpoints.
func mnaEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.HandleMethodNotAllowed = true
	r.DELETE("/internal/purge", func(c *gin.Context) { c.String(http.StatusOK, "purged") })
	r.POST("/internal/item", func(c *gin.Context) { c.String(http.StatusOK, "created") })
	r.PUT("/internal/item", func(c *gin.Context) { c.String(http.StatusOK, "updated") })
	return r
}

// VULN-006 — UseH2C: the server speaks cleartext HTTP/2 (h2c) on every connection.
func h2cEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.UseH2C = true
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"proto": c.Request.Proto, "h2c": "served"})
	})
	r.GET("/internal/admin", func(c *gin.Context) { // a path a proxy might gate on HTTP/1.1
		c.JSON(http.StatusOK, gin.H{"admin": "reached over " + c.Request.Proto})
	})
	return r
}

// VULN-001 escalation — a root-level /:tenant route makes the first path segment (and thus
// the empty-prefix redirect host) fully attacker-chosen.
func rparamEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/:tenant", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"tenant": c.Param("tenant")})
	})
	return r
}

func serve(name, addr string, e *gin.Engine) {
	go func() {
		log.Printf("[%s] listening on %s", name, addr)
		if err := e.Run(addr); err != nil {
			log.Printf("[%s] server error: %v", name, err)
		}
	}()
}

func main() {
	gin.SetMode(gin.ReleaseMode) // release: closer to production; isolates behavior from debug extras
	serve("demo", ":8090", demoEngine())
	serve("tp", ":8091", tpEngine())
	serve("rawpath", ":8092", rawPathEngine())
	serve("slash", ":8093", slashEngine())
	serve("fixed", ":8094", fixedPathEngine())
	serve("mna", ":8095", mnaEngine())
	serve("h2c", ":8096", h2cEngine())
	serve("rparam", ":8097", rparamEngine())
	fmt.Println("gin extended harness up (engines 8090-8097)")
	select {} // block forever
}
