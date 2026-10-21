module cvehunter/ginextharness

go 1.26.0

require github.com/gin-gonic/gin v1.12.0

// Audit target: build gin from the local checkout, not the module proxy.
// The Docker build copies targets/gin into /src/gin (see Dockerfile).
replace github.com/gin-gonic/gin => /src/gin
