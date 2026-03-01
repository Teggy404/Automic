import { Bolt } from "lucide-react";
import { Input } from "../../ui/input";
import { Textarea } from "../../ui/textarea";
import { Button } from "../../ui/button";
const DiagnoseEntry = () => {
  return ( 
    <div className="w-full h-full rounded-2xl border border-black/10 bg-black/10 p-6 flex flex-col items-center justify-center gap-5">

      <div className="flex flex-col items-center gap-5">
        <Bolt
          className="opacity-70 glow-spin"
          style={{ animationDuration: "1s", width: 44, height: 44 }}
        />
        <span className="text-lg font-semibold text-black">
          Use Ai to Identify the job 
        </span>
        <span className="text-sm text-black/60 text-center max-w-sm">
          Our system reference thousands of public records to help you diagnose an issue.
          For the most accurate job recommendation, please provide an OBD fault code and 
          be as descriptive as possible. 
        </span>

        <form className="w-full flex flex-col gap-2">
          <Input 
            placeholder="OBD Code"
            className="h-11 bg-white/90 text-black placeholder:text-black/50 border border-black/10 focus-visible:ring-2 focus-visible:ring-white/30"/>
          <Textarea 
            placeholder="Symptom Description"
            className="h-11 bg-white/90 text-black placeholder:text-black/50 border border-black/10 focus-visible:ring-2 focus-visible:ring-white/30"/>
          <Button>Submit</Button>
        </form>
      </div>
    </div>
   );
}
 
export default DiagnoseEntry;