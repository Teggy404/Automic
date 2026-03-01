import JobEntry from "./JobEntry";

const CarPane = () => {
  return (   
    <div className="flex flex-col bg-gray-100 rounded-2xl h-full drop-shadow-lg p-10">
      <div className="text-center mb-5">
        <span className="font-bold text-2xl text-shadow-lg">Honda CRV 2004</span>
      </div>
      <JobEntry/>
    </div>

   );
}
 
export default CarPane;