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
