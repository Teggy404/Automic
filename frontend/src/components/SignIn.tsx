import { Button } from "./ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./ui/dialog";
import { Field, FieldGroup } from "./ui/field";
import { Input } from "./ui/input";

const SignIn = () => {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button
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

          <form className="mt-6 grid gap-4">
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

            <Button className="h-11 w-full font-bold">
              Sign In
            </Button>
          </form>
        </div>
        <div className="border-t bg-muted/40 px-8 py-5">
          <div className="flex items-center justify-between">
            <p className="text-sm opacity-80">New here?</p>
            <Button type="button" variant="link" className="px-0 font-bold">
              Create an account
            </Button>
          </div>
          <DialogFooter className="mt-4">
            <DialogClose asChild>
              <Button type="button" variant="ghost" className="w-full bg-secondary">
                Cancel
              </Button>
            </DialogClose>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default SignIn;