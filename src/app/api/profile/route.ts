import { NextRequest, NextResponse } from "next/server";
import { validateKindeJWT } from "@/utils/kinde-jwt";

export async function GET(request: NextRequest) {
  // Check for Bearer token in Authorization header (case-insensitive)
  const authHeader =
    request.headers.get("authorization") ||
    request.headers.get("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Extract token from Bearer header
  const token = authHeader.substring(7).trim();

  // Validate token is not empty
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Validate token using JWT validator
  const decodedToken = await validateKindeJWT(token);
  if (!decodedToken) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Return email when token is valid
  return NextResponse.json({
    email: "gexofo9447@httpsu.com",
  });
}
