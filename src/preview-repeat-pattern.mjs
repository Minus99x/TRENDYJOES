/** Bounded repeated artwork coordinates for local pattern previews. */
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&n>0&&n<=10000;
export function tilePreviewPattern({zoneWidth,zoneHeight,tileWidth,tileHeight,gapX=0,gapY=0,stagger=false}={}){
 if(![zoneWidth,zoneHeight,tileWidth,tileHeight].every(finite)||![gapX,gapY].every(x=>typeof x==='number'&&Number.isFinite(x)&&x>=0&&x<=10000)||typeof stagger!=='boolean')throw new RangeError('PREVIEW_PATTERN_INPUT');
 const strideX=tileWidth+gapX,strideY=tileHeight+gapY,rows=Math.ceil(zoneHeight/strideY),columns=Math.ceil(zoneWidth/strideX)+Number(stagger);
 if(rows*columns>256)throw new RangeError('PREVIEW_PATTERN_TOO_MANY_TILES');
 const cells=[];for(let r=0;r<rows;r++){const offset=stagger&&r%2===1?strideX/2:0;for(let c=0;c<columns;c++){const x=c*strideX+offset,y=r*strideY;if(x<zoneWidth&&y<zoneHeight)cells.push(Object.freeze({x,y,visibleWidth:Math.min(tileWidth,zoneWidth-x),visibleHeight:Math.min(tileHeight,zoneHeight-y)}));}}
 return Object.freeze({schema:'TJ-PREVIEW-PATTERN-1',tileCount:cells.length,cells:Object.freeze(cells),localOnly:true,manufacturingApproved:false});
}
