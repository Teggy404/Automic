const CarPane = () => {
  return (   
    <div className="bg-gray-100 rounded-2xl h-[80%] drop-shadow-lg p-10">
      <div className="text-center mb-5">
        <span className="font-bold text-2xl text-shadow-lg">Honda CRV 2004</span>
      </div>
      <div className="flex flex-col items-center h-[90%] gap-15">
        <img src="/cars/CAB40HOS021B0112.webp" className="rounded-2xl w-100 h-75 border-gray-200 drop-shadow-lg"/>
        <span className="text-gray-400">Diagnosis: Describe Symptoms below to get started</span>
      </div>
    </div>

   );
}
 
export default CarPane;