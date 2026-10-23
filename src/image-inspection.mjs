/** Decode enough of a raster header to reject mismatched/truncated media before local staging.
 * This is NOT a malware scanner or a production image decoding pipeline.
 */
const fail=(message)=>{throw new Error(message)};
const MAX_PX=10000, MAX_AREA=48_000_000;
function check(w,h){if(!Number.isInteger(w)||!Number.isInteger(h)||w<1||h<1||w>MAX_PX||h>MAX_PX||w*h>MAX_AREA)fail('Image dimensions outside local preview policy');return {width:w,height:h};}
function png(buf){
 if(buf.length<33||!buf.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) fail('Invalid PNG signature');
 if(buf.readUInt32BE(8)!==13||buf.toString('ascii',12,16)!=='IHDR')fail('Missing PNG IHDR');
 const {width,height}=check(buf.readUInt32BE(16),buf.readUInt32BE(20));
 const type=buf[25],compression=buf[26],filter=buf[27],interlace=buf[28];
 if(![0,2,3,4,6].includes(type)||compression!==0||filter!==0||![0,1].includes(interlace))fail('Unsupported PNG header');
 // Validate IHDR integrity; an image decoder / scanner is still required for production.
 let crc=0xffffffff;for(let i=12;i<29;i++){crc^=buf[i];for(let j=0;j<8;j++)crc=(crc>>>1)^(0xedb88320&-(crc&1));}
 crc=(crc^0xffffffff)>>>0;if(crc!==buf.readUInt32BE(29))fail('PNG IHDR checksum mismatch');
 if(buf.indexOf(Buffer.from('IDAT'))<0||buf.indexOf(Buffer.from('IEND'))<0)fail('Incomplete PNG structure');
 return {mediaType:'image/png',width,height,extension:'png'};
}
function jpeg(buf){
 if(buf.length<64||buf[0]!==0xff||buf[1]!==0xd8||buf.at(-2)!==0xff||buf.at(-1)!==0xd9)fail('Incomplete JPEG markers');
 let i=2, width, height, scanned=false;
 while(i<buf.length-4){
  if(buf[i]!==0xff){if(scanned)break;fail('Malformed JPEG segment');}
  while(buf[i]===0xff)i++;const marker=buf[i++];
  if(marker===0xd9)break;if(marker===0xd8||marker===0x01||(marker>=0xd0&&marker<=0xd7))continue;
  if(i+2>buf.length)fail('Truncated JPEG segment');
  const size=buf.readUInt16BE(i);if(size<2||i+size>buf.length)fail('Invalid JPEG segment length');
  if([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker)){
   if(size<7)fail('Truncated JPEG dimensions');height=buf.readUInt16BE(i+3);width=buf.readUInt16BE(i+5);
  }
  if(marker===0xda)scanned=true;
  i+=size;
 }
 if(!scanned||!width||!height)fail('JPEG image frame missing');
 return {...check(width,height),mediaType:'image/jpeg',extension:'jpg'};
}
function webp(buf){
 if(buf.length<30||buf.toString('ascii',0,4)!=='RIFF'||buf.toString('ascii',8,12)!=='WEBP')fail('Invalid WebP signature');
 const declared=buf.readUInt32LE(4)+8;if(declared!==buf.length)fail('Incomplete WebP RIFF data');
 let off=12,width,height;
 while(off+8<=buf.length){const type=buf.toString('ascii',off,off+4),size=buf.readUInt32LE(off+4),data=off+8;
  if(data+size>buf.length)fail('Invalid WebP chunk');
  if(type==='VP8X'&&size>=10){width=1+buf.readUIntLE(data+4,3);height=1+buf.readUIntLE(data+7,3);}
  if(type==='VP8L'&&size>=5&&buf[data]===0x2f){let bits=buf.readUInt32LE(data+1);width=(bits&0x3fff)+1;height=((bits>>>14)&0x3fff)+1;}
  if(type==='VP8 '&&size>=10&&buf[data+3]===0x9d&&buf[data+4]===0x01&&buf[data+5]===0x2a){width=buf.readUInt16LE(data+6)&0x3fff;height=buf.readUInt16LE(data+8)&0x3fff;}
  off=data+size+(size%2);if(width&&height)break;
 }
 if(!width||!height)fail('WebP dimensions not found');
 return {...check(width,height),mediaType:'image/webp',extension:'webp'};
}
export function inspectRaster(bytes, claimedType){
 const buf=Buffer.from(bytes);if(buf.length<30)fail('Artwork too small');
 const actual=buf[0]===137?png(buf):(buf[0]===255&&buf[1]===216?jpeg(buf):(buf.toString('ascii',0,4)==='RIFF'?webp(buf):fail('Only raster PNG/JPEG/WebP accepted in local prototype')));
 if(claimedType&&claimedType.split(';')[0].trim().toLowerCase()!==actual.mediaType)fail('Artwork content-type mismatch');
 return actual;
}
