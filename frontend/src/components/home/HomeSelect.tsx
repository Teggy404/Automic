import { Button } from "../ui/button"
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "../ui/command"
import { useState } from "react";

type HomeSelectProps<T> = {
    name: string;
    value: string | undefined;
    data: T[] | undefined;
    onChange: (value:T) => void
    getKey: (item: T) => string;
    getName: (item: T) => string;
}

const HomeSelect = <T,>( props:HomeSelectProps<T>) => {
    const [open, setOpen] = useState(false);
    const [query, setQuery] = useState("");

    const filtered = (props.data ?? []).filter((item) => {
      return props.getName(item).toLowerCase().includes(query.toLowerCase());
    })
    .slice(0, 50);

    return (
      <div className="pt-5">
        <Button onClick={() => setOpen(true)} type="button" variant={props.value ? "secondary":"default"} className={"w-full hover:cursor-pointer"}>
          {props.value ?? `Select ${props.name}`}
        </Button>
        <CommandDialog open={open} onOpenChange={setOpen}>
          <Command>
            <CommandInput placeholder={`Search ${props.name}...`}  value={query} onValueChange={setQuery}/>
            <CommandList>
              <CommandEmpty>No results found.</CommandEmpty>
              <CommandGroup heading="Suggestions">
                {filtered.map((item) => {
                  return (
                  <CommandItem 
                    key={props.getKey(item)} 
                    onSelect={() => {
                      props.onChange(item);
                      setOpen(false);
                    }}>
                      {props.getName(item)}
                  </CommandItem>
                  );
                })} 
              </CommandGroup>
            </CommandList>
          </Command>
        </CommandDialog>
      </div>
      );
}
 
export default HomeSelect;