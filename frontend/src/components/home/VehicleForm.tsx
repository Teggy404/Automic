import { useState, useEffect } from "react";
import HomeSelect from "./HomeSelect";
import { Button } from "../ui/button";
import type { Makes, Make } from "../../types/vpic";
import { getMakes } from "../../api/vpic";

type VehicleFormProps = {
    setIconGlow: (value: number) => void;
}
const VehicleForm = ({setIconGlow}:VehicleFormProps) => {
    const [makes, setMakes] = useState<Make[] | undefined> ();
    const [make, setMake] = useState<string | null>(null);
    const [model, setModel] = useState<string | null>(null);
    const [year, setYear] = useState<string | null>(null);

    useEffect(() =>{
      const loadMakes = async () => {
        const data = await getMakes();
        setMakes(data);
      };
      loadMakes();
    }, []);

    return ( 
        <form>
          <HomeSelect<Make> 
          name={"Make"} 
          value={make} 
          data={makes} 
          getKey={(m) => String(m.id)} 
          getName={(m) => m.name} 
          onChange={(v) => {
            setMake(v);
            setModel(null);
            setYear(null);
            setIconGlow(0);
          }}/>
          {/* {make && <HomeSelect 
          name={"Model"} 
          value={model} 
          onChange={(v) => {
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
            </Button>} */}
        </form>
     );
}
 
export default VehicleForm;