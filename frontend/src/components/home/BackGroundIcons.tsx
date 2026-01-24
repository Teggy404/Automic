import { Car, Wrench, Bolt } from "lucide-react";
import type { ForwardRefExoticComponent } from "react";
import type { LucideProps } from "lucide-react";
import type { RefAttributes } from "react";

type IconSpec = {
    Icon: ForwardRefExoticComponent<Omit<LucideProps, "ref"> & RefAttributes<SVGSVGElement>>
    top: string;
    left: string;
    sizePx: number;
    opacity: number;
    durationSec: number;
    delaySec: number;
}

const randomInt = (min: number, max: number) => {
    return Math.floor(Math.random() * (max - min + 1) + min);
}

const icons: IconSpec[] = [
  
  { Icon: Bolt, top: `25%`, left: "-2%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "-2%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "-2%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "-2%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 }, 

  { Icon: Bolt, top: `15%`, left: "7%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "7%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "7%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "7%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "8%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `25%`, left: "17%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "17%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "17%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "17%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `15%`, left: "27%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "27%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "27%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "27%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "27%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `25%`, left: "37%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "37%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "37%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "37%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `15%`, left: "47%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "47%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "47%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "47%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "47%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `25%`, left: "57%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "57%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "57%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "57%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `15%`, left: "67%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "67%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "67%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "67%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "67%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `25%`, left: "77%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "77%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "77%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "77%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `15%`, left: "87%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `33%`, left: "87%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `51%`, left: "87%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `68%`, left: "87%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `85%`, left: "87%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },

  { Icon: Bolt, top: `25%`, left: "96%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `43%`, left: "96%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `61%`, left: "96%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 },
  { Icon: Bolt, top: `78%`, left: "96%", sizePx: 100, opacity: 0.08, durationSec: randomInt(1, 5),  delaySec: 0 }, 
]

const BackGroundIcons = () => {
    return ( 
        <div className="absolute inset-0 overflow-hidden pointer-events-none z-1">
            {icons.map(({ Icon, top, left, sizePx, opacity, durationSec, delaySec }, i) => (
                <Icon
                    key={i}
                    className="bg-icon absolute text-slate-950"
                    style={{
                        top,
                        left,
                        width: sizePx,
                        height: sizePx,
                        opacity,
                        animationDuration: `${durationSec}s`,
                        animationDelay: `${delaySec}s`,
                    }}
                />
            ))}
        </div>
     );
}
 
export default BackGroundIcons;