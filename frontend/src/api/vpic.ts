import { apiFetch } from "./client"
import type { Makes, Models } from "../types/vpic"

export function getMakes(): Promise<Makes> {
    return apiFetch<Makes>("/vehicle/makes", { method: "GET"});
}

export function getModels(makeId:number): Promise<Models>{
    return apiFetch<Models>(`/vehicles/models/${makeId}`, {method: "GET"});
}