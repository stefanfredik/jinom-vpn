package middleware

import (
	"crypto/subtle"

	"github.com/gofiber/fiber/v2"
)

// APIKeyAuth returns a middleware that validates the X-API-Key header.
//
// Security policy:
//   - If apiKey is empty (misconfigured deployment), the endpoint returns 503
//     instead of silently allowing all traffic.
//   - API key is only accepted from the X-API-Key header — NOT from query
//     parameters, which leak in server logs, browser history, and referrers.
//   - Uses constant-time comparison to protect against timing attacks.
func APIKeyAuth(apiKey string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if apiKey == "" {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"success": false,
				"error": fiber.Map{
					"code":    "SERVICE_UNAVAILABLE",
					"message": "API key not configured — set the API_KEY environment variable",
				},
			})
		}

		key := c.Get("X-API-Key")
		if key == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"error": fiber.Map{
					"code":    "UNAUTHORIZED",
					"message": "missing API key — send it via the X-API-Key header",
				},
			})
		}

		// Use constant-time byte comparison to prevent side-channel timing attacks
		if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) != 1 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"error": fiber.Map{
					"code":    "UNAUTHORIZED",
					"message": "invalid API key",
				},
			})
		}

		return c.Next()
	}
}
