import { apiFetch } from "./client";
import type { AuthToken, LoginRequest, RegisterRequest, User } from "../types/auth";

export function getMe(): Promise<User> {
  return apiFetch<User>("/auth/me", { method: "GET" });
}

export function register(payload: RegisterRequest): Promise<AuthToken> {
  return apiFetch<AuthToken>("/auth/register", 
    { 
      method: "POST", 
      body: JSON.stringify(payload)
    });
}

export function login(payload: LoginRequest): Promise<AuthToken> {
  return apiFetch<AuthToken>("/auth/login",
    {
      method: "POST",
      body: JSON.stringify(payload)
    }
  )
}