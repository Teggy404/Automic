import { Button } from "./ui/button";
import { Car } from "lucide-react";

const Navbar = () => {
  return (
    <div className="relative border flex items-center bg-gray-100 p-5 drop-shadow-lg">
      <div>
        <Car size={50} />
      </div>
      <div className="absolute left-1/2 -translate-x-1/2 font-bold text-5xl">Automic</div>
      <div className="ml-auto flex gap-4">
        <Button
          variant={"secondary"}
          className="border border-black hover:cursor-pointer"
        >
          <span className="font-bold">Sign in</span>
        </Button>
        <Button className="hover:cursor-pointer"><span className="font-bold">Register</span></Button>
      </div>
    </div>
  );
};

export default Navbar;
