export type User = {
  id: string;
  userName: string;
};

export type AuthStatus = "loading" | "authed" | "unauthed";

export type AuthState = {
  user: User | null;
  status: AuthStatus;
  bootstrapped: boolean;
  bootstrap: () => Promise<void>;
};

export type AuthResponse = {
  Message: string
}

export type RegisterRequest = {
  Email: string,
  Password: string
}

export type LoginRequest = {
  Email: string,
  Password: string,
}
