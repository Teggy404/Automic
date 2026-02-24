import { apiFetch } from "./client";
import type { Makes, Models, Years } from "../types/vehicle";

export function getMakes(): Promise<Makes> {
  return apiFetch<Makes>("/vehicle/makes", { method: "GET" });
}

export function getModels(make: string): Promise<Models> {
  return apiFetch<Models>(`/vehicle/models/${make}`, { method: "GET" });
}

export function getYears(make: string, model: string): Promise<Years> {
  return apiFetch<Years>(`/vehicle/years/${make}/${model}`, { method: "GET" });
}
