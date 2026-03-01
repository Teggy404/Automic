import { Carousel, CarouselContent, CarouselItem } from "../../ui/carousel";
import { Card, CardContent } from "../../ui/card";
import ManualEntry from "./ManualEntry";
import DiagnoseEntry from "./DiagnoseEntry";

const JobEntryCarousel = () => {
  return (
    <Carousel className="w-full h-full">
      <CarouselContent className="h-full">

        <CarouselItem>
          <ManualEntry/>
        </CarouselItem>

        <CarouselItem>
          <DiagnoseEntry/>
        </CarouselItem>
      </CarouselContent>
    </Carousel>
  );
};


export default JobEntryCarousel;