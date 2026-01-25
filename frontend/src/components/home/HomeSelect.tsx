import { Select, SelectTrigger, SelectValue, SelectContent, SelectGroup, SelectLabel, SelectItem} from "../ui/select";

type HomeSelectProps = {
    name: string;
    value: string | null;
    onChange: (value:string) => void
}

const HomeSelect = ( props:HomeSelectProps) => {
    return (
        <Select 
          value={props.value ?? ""}
          onValueChange={props.onChange}
        >
            <SelectTrigger className={`          
              w-full mt-5 hover:cursor-pointer font-bold
              ${props.value !== null ? "text-black bg-gray-200" : "text-white bg-primary"}
            `}>
              <SelectValue placeholder={`Select ${props.name}`} />
            </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectLabel>Make</SelectLabel>
                  <SelectItem value="apple">Apple</SelectItem>
                  <SelectItem value="banana">Banana</SelectItem>
                  <SelectItem value="blueberry">Blueberry</SelectItem>
                  <SelectItem value="grapes">Grapes</SelectItem>
                  <SelectItem value="pineapple">Pineapple</SelectItem>
                </SelectGroup>
              </SelectContent>
          </Select> );
}
 
export default HomeSelect;