import { apiFetch } from "./client";
import type {AuthResponse, LoginRequest, RegisterRequest, User } from "../types/auth";

export function getMe(): Promise<User> {
  return apiFetch<User>("/auth/me", { method: "GET" });
}

export function register(payload: RegisterRequest): Promise<AuthResponse> {
  return apiFetch<AuthResponse>("/auth/register", 
    { 
      method: "POST", 
      body: JSON.stringify(payload)
    });
}

export function login(payload: LoginRequest): Promise<AuthResponse> {
  return apiFetch<AuthResponse>("/auth/login",
    {
      method: "POST",
      body: JSON.stringify(payload)
    }
  )
}