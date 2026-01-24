import { Select, SelectTrigger, SelectValue, SelectContent, SelectGroup, SelectLabel, SelectItem} from "../ui/select";

type HomeSelectProps = {
    name: string;
}

const HomeSelect = ( props:HomeSelectProps) => {
    return (
        <Select>
            <SelectTrigger className="
              w-full 
              bg-gray-200 
              mt-5 
              hover:cursor-pointer 
              font-bold 
              data-placeholder:bg-primary
              data-placeholder:text-white ">
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