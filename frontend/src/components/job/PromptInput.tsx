import { Input } from "../ui/input";

const PromptInput = () => {
  return ( 
    <div className="bg-gray-100 rounded-full h-[10%] drop-shadow-lg flex items-center-safe px-5">
      <Input 
        className="
          border-0 
          focus-visible:ring-0 
          focus-visible:outline-none 
          shadow-none text-gray-500 
          text-xl!" 
        placeholder="Enter vehicle fault code or Describe symptoms"
      />
    </div>
   );
}
 
export default PromptInput;