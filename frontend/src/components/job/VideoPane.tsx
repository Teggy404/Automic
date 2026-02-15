import { useState } from "react";
import { VideoOff } from "lucide-react";
const VideoPane = () => {
  const [videos, setVideos] = useState<number>(0);
  return ( 
    <div className={`
      bg-gray-100 rounded-2xl h-full drop-shadow-lg flex 
      ${!videos ? 'items-center justify-center' : 'p-4'}
    `}>
      {videos ? (
        <div>Videos!</div>
      ) : (
        <div className="flex-col">
          <VideoOff className="w-20! h-20! text-black/25!"/>
          <span className="text-black/40! font-bold">No Videos</span>
        </div>
      )}
    </div> 
  );
}
 
export default VideoPane;


