import { useState, useEffect } from "react";
import HomeSelect from "./HomeSelect";
import { Button } from "../ui/button";
import type { Make, Model } from "../../types/vpic";
import { getMakes, getModels } from "../../api/vpic";

type VehicleFormProps = {
    setIconGlow: (value: number) => void;
}

const generateYears = (startYear: number):number[] => {
  const currentYear = new Date().getFullYear();
  const years: number[] = [];

  for(let y = startYear; y <= currentYear; y++){
    years.push(y);
  }

  return years;
}

const VehicleForm = ({setIconGlow}:VehicleFormProps) => {
    const [makes, setMakes] = useState<Make[] | undefined> ();
    const [models, setModels] = useState<Model[] | undefined> ();
    const [make, setMake] = useState<Make | null>(null);
    const [model, setModel] = useState<Model | null>(null);
    const [year, setYear] = useState<string | null>(null);
    
    const years = generateYears(1950).reverse();

    useEffect(() =>{
      const loadMakes = async () => {
        const data = await getMakes();
        setMakes(data);
      };
      loadMakes();
    }, []);

    useEffect(() => {
      const loadModels = async (m:Make | null) => {
        if(m){
          const data = await getModels(m.id);
          setModels(data);
          console.log(data);
        }
      }
      loadModels(make);
    }, [make])

    console.log(make);
    return ( 
        <form>
          <HomeSelect<Make> 
          name={"Make"} 
          value={make?.name} 
          data={makes} 
          getKey={(m) => String(m.id)} 
          getName={(m) => m.name} 
          onChange={(v) => {
            setMake(v);
            setModel(null);
            setYear(null);
            setIconGlow(0);
          }}/>
          {make && <HomeSelect<Model> 
          name={"Model"} 
          value={model?.name}
          data={models}
          getKey={(m) => String(m.id)}
          getName={(m) => m.name} 
          onChange={(v) => {
            setModel(v);
            setYear(null);
            setIconGlow(1);
          }}/> }
          {model && <HomeSelect<number> 
            name={"Year"} 
            value={year ?? undefined}
            data={years}
            getKey={(y)=>String(y)}
            getName={(y)=>String(y)}
            onChange={(v) => {
              setYear(String(v));
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