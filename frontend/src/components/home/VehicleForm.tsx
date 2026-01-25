import { useState } from "react";
import HomeSelect from "./HomeSelect";
import { Button } from "../ui/button";

type VehicleFormProps = {
    setIconGlow: (value: number) => void;
}
const VehicleForm = ({setIconGlow}:VehicleFormProps) => {
    const [make, setMake] = useState<string | null>(null);
    const [model, setModel] = useState<string | null>(null);
    const [year, setYear] = useState<string | null>(null);



    return ( 
        <form>
          <HomeSelect name={"Make"} value={make} onChange={(v) => {
            setMake(v);
            setModel(null);
            setYear(null);
            setIconGlow(0);
          }}/>
          {make && <HomeSelect name={"Model"} value={model} onChange={(v) => {
            setModel(v);
            setYear(null);
            setIconGlow(1);
          }}/> }
          {model && <HomeSelect name={"Year"} value={year} onChange={(v) => {
            setYear(v);
            setIconGlow(2);
          }}/>}
          {make && model && year && 
            <Button type="submit" className="w-full mt-5 hover:cursor-pointer" >
                Submit
            </Button>}
        </form>
     );
}
 
export default VehicleForm;