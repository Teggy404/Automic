import { Select, SelectTrigger, SelectValue, SelectContent, SelectGroup, SelectLabel, SelectItem } from "../components/ui/select";
import BackGroundIcons from "../components/home/BackGroundIcons";
import HomeSelect from "../components/home/HomeSelect";

const HomePage = () => {

  return (
    <div className="flex-1 bg-secondary ">
      <BackGroundIcons/>

      <div className="relative flex h-full justify-center items-center z-2">
        <div className="border rounded-2xl bg-gray-100 p-10 shadow-lg">
          <span className="font-bold animate-pulse text-2xl">Lets Start fixing...</span>
          <HomeSelect name={"Make"}/>
          <HomeSelect name={"Model"}/>
          <HomeSelect name={"Year"}/>
        </div>
      </div>      
    </div>
  );
}
 
export default HomePage;