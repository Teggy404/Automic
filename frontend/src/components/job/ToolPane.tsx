import { Wrench } from "lucide-react";
import { useState } from "react";
const ToolPane = () => {
  const [tools, setTools] = useState<number>(0);

  return (  
    <div className={`
      bg-gray-100 rounded-2xl h-full drop-shadow-lg flex 
      ${!tools ? 'items-center justify-center' : 'p-4'}
    `}>
      {tools ? (
        <div>Tools!</div>
      ) : (
        <div className="flex-col">
          <Wrench className="w-20! h-20! text-black/25!"/>
          <span className="text-black/40! font-bold">No Tools</span>
        </div>
      )}
    </div>
  );
}

export default ToolPane;