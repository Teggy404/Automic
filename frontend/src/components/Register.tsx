import { Button } from "./ui/button";
import {
  Dialog,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogContent,
} from "./ui/dialog";
import { FieldGroup, Field } from "./ui/field";
import { Input } from "./ui/input";
import { useState } from "react";
import { register } from "../api/auth";
import { ApiError } from "../api/client";
import { toast } from "sonner";

const Register = () => {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const canRegister =
    email.trim().length > 0 &&
    password.length > 0 &&
    confirmPassword.length > 0 &&
    password === confirmPassword;

  const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {    
      if (!canRegister) return;
      const message = await register({
        Email: email,
        Password: password,
      });
      setOpen(false);
      toast("Account Created Succesfully")
      console.log(message);
    } catch(e){
      if(e instanceof ApiError){
        console.log(e.status, e.data);
      } else console.log(e);
      toast("Account Creation Failed")
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="hover:cursor-pointer" onClick={() => setOpen(true)}>
          <span className="font-bold">Register</span>
        </Button>
      </DialogTrigger>

      <DialogContent className="sm:max-w-sm p-0 overflow-hidden">
        <div className="p-8 pb-6">
          <DialogHeader className="space-y-2">
            <DialogTitle className="text-2xl">
              <span className="font-extrabold tracking-tight">
                Create Account
              </span>
            </DialogTitle>
            <DialogDescription className="text-sm leading-relaxed">
              Create an account to organize you jobs and workspace
            </DialogDescription>
          </DialogHeader>

          <form className="mt-6 grid gap-4" onSubmit={onSubmit}>
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
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </Field>

              <Field className="grid gap-2">
                <label htmlFor="password" className="text-sm font-semibold">
                  password
                </label>

                <Input
                  id="password"
                  name="password"
                  type="password"
                  placeholder="••••••••"
                  className="h-11 pr-16"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </Field>

              <Field className="grid gap-2">
                <label htmlFor="password" className="text-sm font-semibold">
                  confirm password
                </label>

                <Input
                  id="confirmPassword"
                  name="confirmPassword"
                  type="password"
                  placeholder="••••••••"
                  className="h-11 pr-16"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                />
              </Field>
            </FieldGroup>
            <Button className="h-11 w-full font-bold" disabled={!canRegister}>
              Register
            </Button>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default Register;
