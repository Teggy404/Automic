import { Car, Wrench, Bolt } from "lucide-react";
import type { ForwardRefExoticComponent } from "react";
import type { LucideProps } from "lucide-react";
import type { RefAttributes } from "react";

type iconBackgroundProps = {
    iconGlow: number;
}
type IconSpec = {
    Icon: ForwardRefExoticComponent<Omit<LucideProps, "ref"> & RefAttributes<SVGSVGElement>>
    top: string;
    left: string;
    sizePx: number;
    delaySec: number;
}

const randomInt = (min: number, max: number) => {
    return Math.floor(Math.random() * (max - min + 1) + min);
}

const icons: IconSpec[] = [
  
  { Icon: Bolt, top: `5%`, left: "-2%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `25%`, left: "-2%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "-2%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "-2%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "-2%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `95%`, left: "-2%", sizePx: 100, delaySec: 0 }, 

  { Icon: Bolt, top: `15%`, left: "7%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "7%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "7%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "7%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "8%", sizePx: 100, delaySec: 0 },

  { Icon: Bolt, top: `5%`, left: "17%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `25%`, left: "17%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "17%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "17%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "17%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `95%`, left: "17%", sizePx: 100, delaySec: 0 }, 

  { Icon: Bolt, top: `15%`, left: "27%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "27%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "27%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "27%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "27%", sizePx: 100, delaySec: 0 },

  { Icon: Bolt, top: `5%`, left: "37%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `25%`, left: "37%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "37%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "37%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "37%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `95%`, left: "37%", sizePx: 100, delaySec: 0 }, 

  { Icon: Bolt, top: `15%`, left: "47%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "47%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "47%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "47%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "47%", sizePx: 100, delaySec: 0 },

  { Icon: Bolt, top: `5%`, left: "57%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `25%`, left: "57%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "57%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "57%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "57%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `95%`, left: "57%", sizePx: 100, delaySec: 0 },

  { Icon: Bolt, top: `15%`, left: "67%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "67%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "67%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "67%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "67%", sizePx: 100, delaySec: 0 },

  { Icon: Bolt, top: `5%`, left: "77%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `25%`, left: "77%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "77%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "77%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "77%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `95%`, left: "77%", sizePx: 100, delaySec: 0 },

  { Icon: Bolt, top: `15%`, left: "87%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "87%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "87%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "87%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "87%", sizePx: 100, delaySec: 0 },

  { Icon: Bolt, top: `5%`, left: "96%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `25%`, left: "96%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "96%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "96%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "96%", sizePx: 100, delaySec: 0 },
  { Icon: Bolt, top: `95%`, left: "96%", sizePx: 100, delaySec: 0 },
  

]

const BackGroundIcons = ({iconGlow}: iconBackgroundProps) => {
    return ( 
        <div className="absolute inset-0 overflow-hidden pointer-events-none z-1">
            {icons.map(({ Icon, top, left, sizePx, delaySec }, i) => (
                <Icon
                    key={i}
                    className={`
                        absolute text-slate-950
                        transition-opacity duration-700 ease-in-out 
                        ${i%3 <= iconGlow ? "opacity-50 glow-spin" : "opacity-10 bg-icon"}`}
                    style={{
                        top,
                        left,
                        width: sizePx,
                        height: sizePx,
                        animationDuration: `${i%3 <= iconGlow ? 1 : randomInt(3, 5)}s`,
                    }}
                />
            ))}
        </div>
     );
}
 
export default BackGroundIcons;