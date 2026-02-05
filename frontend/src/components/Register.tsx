import { Button } from "./ui/button";
import { Dialog, DialogDescription, DialogHeader, DialogTitle, DialogTrigger,DialogContent } from "./ui/dialog";
import { FieldGroup, Field } from "./ui/field";
import { Input } from "./ui/input";

const Register = () => {
    return (
        <Dialog>
            <DialogTrigger asChild>
                <Button className="hover:cursor-pointer">
                    <span className="font-bold">Register</span>
                </Button>
            </DialogTrigger>

            <DialogContent className="sm:max-w-sm p-0 overflow-hidden">
                <div className="p-8 pb-6">
                    <DialogHeader className="space-y-2">
                        <DialogTitle className="text-2xl">
                            <span className="font-extrabold tracking-tight">Create Account</span>
                        </DialogTitle>
                        <DialogDescription className="text-sm leading-relaxed">
                            Create an account to organize you jobs and workspace
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
                                    password
                                </label>

                                <Input 
                                    id="password" 
                                    name="password" 
                                    type="password"
                                    placeholder="••••••••"
                                    className="h-11 pr-16"
                                />

                            </Field>

                            <Field className="grid gap-2">
                                <label htmlFor="password" className="text-sm font-semibold">
                                    confirm password
                                </label>

                                <Input 
                                    id="password" 
                                    name="password" 
                                    type="password"
                                    placeholder="••••••••"
                                    className="h-11 pr-16"
                                />
                            </Field>
                        </FieldGroup>
                        <Button className="h-11 w-full font-bold">
                            Register
                        </Button>
                    </form>
                </div>
            </DialogContent>
        </Dialog>
    );
}

export default Register;