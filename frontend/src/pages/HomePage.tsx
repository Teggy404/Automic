import { useState, useEffect } from "react";
import BackGroundIcons from "../components/home/BackGroundIcons";
import VehicleForm from "../components/home/VehicleForm";

const HomePage = () => {
  const [iconGlow, setIconGlow] = useState<number>(-1)

  return (
    <div className="flex-1 bg-secondary ">
      <BackGroundIcons iconGlow={iconGlow}/>

      <div className="relative flex h-full justify-center items-center z-2">
        <div className="border rounded-2xl bg-gray-100 p-10 shadow-lg">
          <span className="font-bold animate-pulse text-2xl">Lets Start fixing...</span>
          <VehicleForm setIconGlow={setIconGlow}/>
        </div>
      </div>      
    </div>
  );
}
 
export default HomePage;