import { useState, useEffect } from "react";
import HomeSelect from "./HomeSelect";
import { Button } from "../ui/button";
import type { Make, Model, Year } from "../../types/vehicle";
import { getMakes, getModels, getYears } from "../../api/vehicle";

type VehicleFormProps = {
  setIconGlow: (value: number) => void;
};

const VehicleForm = ({ setIconGlow }: VehicleFormProps) => {
  const [makes, setMakes] = useState<Make[] | undefined>();
  const [models, setModels] = useState<Model[] | undefined>();
  const [years, setYears] = useState<Year[] | undefined>();
  const [make, setMake] = useState<Make | null>(null);
  const [model, setModel] = useState<Model | null>(null);
  const [year, setYear] = useState<Year | null>(null);

  useEffect(() => {
    const loadMakes = async () => {
      const data = await getMakes();
      setMakes(data);
    };
    loadMakes();
  }, []);

  useEffect(() => {
    const loadModels = async (m: Make | null) => {
      if (m) {
        const data = await getModels(m.name);
        setModels(data);
      }
    };
    loadModels(make);
  }, [make]);

  useEffect(() => {
    const loadYears = async (m: Make | null, mo: Model | null) => {
      if (m && mo) {
        const data = await getYears(m.name, mo.name);
        setYears(data);
        console.log(data);
      }
    };
    loadYears(make, model);
  }, [model, model]);

  console.log(make);
  return (
    <form>
      <HomeSelect<Make>
        name={"Make"}
        value={make?.name}
        data={makes}
        getKey={(m) => String(m.name)}
        getName={(m) => m.name}
        onChange={(v) => {
          setMake(v);
          setModel(null);
          setYear(null);
          setIconGlow(0);
        }}
      />
      {make && (
        <HomeSelect<Model>
          name={"Model"}
          value={model?.name}
          data={models}
          getKey={(m) => String(m.name)}
          getName={(m) => m.name}
          onChange={(v) => {
            setModel(v);
            setYear(null);
            setIconGlow(1);
          }}
        />
      )}
      {model && (
        <HomeSelect<Year>
          name={"Year"}
          value={year?.stringYear}
          data={years}
          getKey={(y) => y.id}
          getName={(y) => y.stringYear}
          onChange={(y) => {
            setYear(y);
            setIconGlow(2);
          }}
        />
      )}
      {make && model && year && (
        <Button type="submit" className="w-full mt-5 hover:cursor-pointer">
          Submit
        </Button>
      )}
    </form>
  );
};

export default VehicleForm;
