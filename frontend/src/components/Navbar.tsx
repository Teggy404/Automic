import { Button } from "./ui/button";
import { Car } from "lucide-react";
import  SignIn  from "./SignIn";
import Register from "./Register";

const Navbar = () => {
  return (
    <div className="relative border flex items-center bg-gray-100 p-5 drop-shadow-lg z-4">
      <div>
        <Car size={50} />
      </div>
      <div className="absolute left-1/2 -translate-x-1/2 font-bold text-5xl">
        Automic
      </div>
      <div className="ml-auto flex gap-4">
        <SignIn />
        <Register />
      </div>
    </div>
  );
};

export default Navbar;
