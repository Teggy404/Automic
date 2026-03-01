import { Bolt, Search, ArrowUp } from "lucide-react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Separator } from "../ui/separator";

const JobEntry = () => {
  return (
    <div className="w-full h-full rounded-2xl border border-black/10 bg-black/10  shadow-lg p-6 flex flex-col items-center justify-center gap-5">

      <div className="flex flex-col items-center gap-5">
          <Bolt
            className="opacity-70 glow-spin"
            style={{ animationDuration: "1s", width: 44, height: 44 }}
          />
        <span className="text-lg font-semibold text-black">
          Do you know what’s wrong with your car?
        </span>
        <span className="text-sm text-black/60 text-center max-w-sm">
          If you know, describe the problem below. Otherwise, click 'diagnose' and we'll start narrowing it down.
        </span>
      </div>

      <div className="w-full max-w-md flex gap-2">
        <Input
          className="h-11 bg-white/90 text-black placeholder:text-black/50 border border-black/10 focus-visible:ring-2 focus-visible:ring-white/30"
          placeholder="e.g. ‘radiator leaking’"
        />
        <Button className="h-11 px-4 hover:cursor-pointer">
          <ArrowUp className="h-4 w-4" />
        </Button>
      </div>

      <div className="w-full max-w-md flex items-center gap-3">
        <Separator className="flex-1 bg-black/10" />
        <span className="text-xs uppercase tracking-wider text-black/40">
          or
        </span>
        <Separator className="flex-1 bg-black/10" />
      </div>

      <Button
        variant="secondary"
        className="h-11 px-5 text-black border border-black hover:cursor-pointer"
      >
        Diagnose
        <Search className="ml-2 h-4 w-4" />
      </Button>
    </div>
  );
};

export default JobEntry;