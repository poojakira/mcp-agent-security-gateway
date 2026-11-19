"use strict";
const view = document.getElementById("view"), image = document.getElementById("diagram"), choice = document.getElementById("choice"), link = document.getElementById("original");
let scale=1,x=0,y=0,drag=null;
function paint(){image.style.transform=`translate(${x}px, ${y}px) scale(${scale})`;document.getElementById("zoom").textContent=Math.round(scale*100)+"%";}
function reset(){scale=1;x=0;y=0;paint();}
function zoom(factor){scale=Math.max(.25,Math.min(6,scale*factor));paint();}
choice.addEventListener("change",()=>{image.src=choice.value;link.href=choice.value;reset();});
document.getElementById("plus").addEventListener("click",()=>zoom(1.25));document.getElementById("minus").addEventListener("click",()=>zoom(.8));document.getElementById("reset").addEventListener("click",reset);
view.addEventListener("pointerdown",event=>{if(event.button!==0)return;drag={id:event.pointerId,px:event.clientX,py:event.clientY,x,y};view.setPointerCapture(event.pointerId);});
view.addEventListener("pointermove",event=>{if(!drag||drag.id!==event.pointerId)return;x=drag.x+event.clientX-drag.px;y=drag.y+event.clientY-drag.py;paint();});
function stop(){drag=null;}view.addEventListener("pointerup",stop);view.addEventListener("pointercancel",stop);
view.addEventListener("keydown",event=>{if(event.key==="+"||event.key==="="){zoom(1.25);event.preventDefault();}if(event.key==="-"){zoom(.8);event.preventDefault();}if(event.key==="0"){reset();event.preventDefault();}});
image.addEventListener("error",()=>{document.getElementById("message").textContent="Diagram unavailable. Use the source architecture document linked above.";});
