import { apiFetch } from "./client";
import type { User } from "../types/auth";

export function getMe(): Promise<User> {
  return apiFetch<User>("/auth/me", { method: "GET" });
}
