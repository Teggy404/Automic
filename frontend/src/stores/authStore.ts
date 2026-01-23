import { create } from "zustand";
import { getMe } from "../api/auth";
import type { AuthState } from "../types/auth";

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  status: "loading",
  bootstrapped: false,
  bootstrap: async () => {
    if (get().bootstrapped) return;
    set({ bootstrapped: true, status: "loading" });
    try {
      const user = await getMe();
      set({ user, status: "authed" });
    } catch (err: any) {
      console.log(err);
      set({ user: null, status: "unauthed" });
    }
    return;
  },
}));
