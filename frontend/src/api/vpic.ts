import { apiFetch } from "./client"
import type { Makes } from "../types/vpic"

export function getMakes(): Promise<Makes> {
    return apiFetch<Makes>("/vehicle/makes", { method: "GET"});
}