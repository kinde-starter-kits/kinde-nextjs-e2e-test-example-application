import { NextRequest, NextResponse } from "next/server";
import { validateKindeJWT } from "@/utils/kinde-jwt";

export async function PATCH(request: NextRequest) {
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

  // Parse request body
  let body;
  try {
    body = await request.json();
  } catch (error) {
    return NextResponse.json(
      { error: "Invalid request body" },
      { status: 400 }
    );
  }

  // Validate theme if provided
  if (body.theme && !["light", "dark"].includes(body.theme)) {
    return NextResponse.json(
      { error: "Invalid theme value. Must be 'light' or 'dark'" },
      { status: 400 }
    );
  }

  // In a real application, you would save the settings to a database here
  // For now, we'll just return success
  return NextResponse.json({
    message: "Settings updated successfully",
    theme: body.theme,
  });
}
