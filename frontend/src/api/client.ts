const BASE_URL = "http://localhost:5148";


//Centralize client side API response handling
export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
  });

  if (res.status == 204) {
    return undefined as T;
  }

  const text = await res.text();
  const data = text ? (JSON.parse(text) as T) : (undefined as T);

  if (!res.ok) {
    throw new ApiError(res.status, data);
  }

  return data;
}

//Custom Exception for API errors
export class ApiError<T = unknown> extends Error{
  public readonly status: number;
  public readonly data: T;
  constructor (status: number, data: T){
    super(`API error ${status}`);
    this.status = status;
    this.data = data
    this.name = "ApiError"
  }
}
