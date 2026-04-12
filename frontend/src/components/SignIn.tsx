import { useState } from "react";
import { Button } from "./ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./ui/dialog";
import { Field, FieldGroup } from "./ui/field";
import { Input } from "./ui/input";
import { login } from "../api/auth";
import type { LoginRequest } from "../types/auth";
import { toast } from "sonner";
import { useAuthStore } from "../stores/authStore";

const SignIn = () => {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const {refresh} = useAuthStore();

  const submitLogin = async (e: React.FormEvent<HTMLFormElement>) =>{
    e.preventDefault();

    if(email && password){
      try{
        await login({
          Email: email,
          Password: password,
        } as LoginRequest)
        await refresh();
        setOpen(false);
      } catch(e:any){
        console.log(e);
        toast("Failed To Login");
      }
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          onClick={() => setOpen(true)}
          variant="secondary"
          className="border border-black hover:cursor-pointer"
        >
          <span className="font-bold">Sign In</span>
        </Button>
      </DialogTrigger>

      <DialogContent className="sm:max-w-sm p-0 overflow-hidden">
        <div className="p-8 pb-6">
          <DialogHeader className="space-y-2">
            <DialogTitle className="text-2xl">
              <span className="font-extrabold tracking-tight">Welcome back</span>
            </DialogTitle>
            <DialogDescription className="text-sm leading-relaxed">
              Sign in to save jobs and personalize your dashboard.
            </DialogDescription>
          </DialogHeader>

          <form className="mt-6 grid gap-4" onSubmit={submitLogin}>
            <FieldGroup>
              <Field className="grid gap-2">
                <label htmlFor="email" className="text-sm font-semibold">
                  Email
                </label>
                
                <Input
                  id="email"
                  name="email"
                  type="email"
                  placeholder="you@example.com"
                  className="h-11"
                  onChange={(e) => {setEmail(e.target.value)}}
                />
              </Field>

              <Field className="grid gap-2">
                  <label htmlFor="password" className="text-sm font-semibold">
                    Password
                  </label>

                <div className="relative">
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="••••••••"
                    className="h-11 pr-16"
                    onChange={(e)=>{setPassword(e.target.value)}}
                  />
                  <button
                    type="button"
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md px-2 py-1 text-xs font-semibold opacity-70 hover:opacity-100"
                  >
                    Show
                  </button>
                </div>
              </Field>
            </FieldGroup>

            <Button className="h-11 w-full font-bold hover:cursor-pointer" type="submit">
              Sign In
            </Button>
          </form>
        </div>
        <div className="border-t bg-muted/40 px-8 py-5">
          <div className="flex items-center justify-between">
            <p className="text-sm opacity-80">New here?</p>
            <Button type="button" variant="link" className="px-0 font-bold hover:cursor-pointer">
              Create an account
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default SignIn;