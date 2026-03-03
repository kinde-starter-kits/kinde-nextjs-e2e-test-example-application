import { validateToken } from "@kinde/jwt-validator";
import { jwtDecoder } from "@kinde/jwt-decoder";

/**
 * Utility function to validate Kinde JWT tokens
 *
 * @param token - The JWT token string to validate
 * @returns Promise that resolves to validation result with user data or null if invalid
 */
export async function validateKindeJWT(
  token: string
): Promise<{ email?: string; [key: string]: any } | null> {
  const domain = process.env.KINDE_ISSUER_URL;
  const expectedAudience = "https://api.mysite.com"; // process.env.KINDE_AUDIENCE;

  if (!domain) {
    console.error("KINDE_ISSUER_URL environment variable is not set");
    return null;
  }

  try {
    // Validate the token
    const result = await validateToken({
      token,
      domain,
    });

    if (!result.valid) {
      console.log("Token validation failed:", result.message);
      return null;
    }

    // Decode after validation
    const decoded = jwtDecoder(token);

    // Check audience claim if KINDE_AUDIENCE is set
    if (expectedAudience) {
      const audience = decoded.aud;
      // Handle both string and array audience values
      const audiences = Array.isArray(audience) ? audience : [audience];

      if (!audiences.includes(expectedAudience)) {
        console.log(
          "Token audience validation failed. Expected:",
          expectedAudience,
          "Got:",
          audience
        );
        return null;
      }
    }

    return decoded as { email?: string; [key: string]: any };
  } catch (error) {
    // The validator throws for JWKS or validation errors
    console.error("Token is invalid:", error);
    return null;
  }
}

/**
 * Type definition for Kinde JWT validation result
 */
export interface KindeJWTValidationResult {
  email?: string;
  sub?: string;
  [key: string]: any;
}
