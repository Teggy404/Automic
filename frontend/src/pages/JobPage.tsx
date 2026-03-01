import BackGroundIcons from "../components/home/BackGroundIcons";
import ToolPane from "../components/job/ToolPane";
import VideoPane from "../components/job/VideoPane";
import CarPane from "../components/job/CarPane";
import PromptInput from "../components/job/PromptInput";
const JobPage = () => {
  return ( 
    <div className="flex-1 bg-secondary">
      <BackGroundIcons iconGlow={-1}/>

      <div className="flex relative h-full z-2">
        <div className="w-[40%] m-10 mr-5">
          <ToolPane/>
        </div>
        <div className="w-full my-10 mx-5 flex flex-col justify-between">
          <CarPane/>
        </div>
        <div className="w-[40%] m-10 ml-5">
          <VideoPane/>
        </div>
      </div>
    </div>
  );
}
 
export default JobPage;