import { Button } from "./ui/button";
import { Car } from "lucide-react";

const Navbar = () => {
  return (
    <div className="border flex bg-gray-100 justify-between p-5 drop-shadow-lg">
      <div className="">
        <Car size={50} />
      </div>
      <div className="font-bold text-5xl">Automic</div>
      <div className="flex gap-4">
        <Button
          variant={"secondary"}
          className="border border-black hover:cursor-pointer"
        >
          Sign in
        </Button>
        <Button className="hover:cursor-pointer">Register</Button>
      </div>
    </div>
  );
};

export default Navbar;
