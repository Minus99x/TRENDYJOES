/** Browser-only local import byte accounting before the GLB inspector. */
const deny=code=>{throw Object.assign(new Error(code),{code});};
/** GLB v2 header only. Inspector must still verify JSON, BIN and mesh content. */
export function validateLocalGlbHeader(bytes){
 if(!(bytes instanceof ArrayBuffer)||bytes.byteLength<24||bytes.byteLength%4!==0)deny('GLB_HEADER_LENGTH');
 const v=new DataView(bytes),n=bytes.byteLength;
 if(v.getUint32(0,true)!==0x46546c67||v.getUint32(4,true)!==2)deny('GLB_HEADER_SIGNATURE');
 if(v.getUint32(8,true)!==n)deny('GLB_HEADER_DECLARED_LENGTH');
 const jsonLength=v.getUint32(12,true);
 if(v.getUint32(16,true)!==0x4e4f534a||jsonLength<4||jsonLength%4!==0||jsonLength>n-20)deny('GLB_HEADER_JSON_CHUNK');
 const next=20+jsonLength;
 if(next<n&&(n-next<8||v.getUint32(next+4,true)!==0x004e4942||v.getUint32(next,true)!==n-next-8))deny('GLB_HEADER_BIN_CHUNK');
 return Object.freeze({byteLength:n,jsonChunkBytes:jsonLength,hasBinaryChunk:next<n,previewOnly:true});
}
export async function readBoundedLocalGlb(file,{limit=16*1024*1024}={}){
 if(!file||typeof file.arrayBuffer!=='function'||!Number.isSafeInteger(file.size)||file.size<20||file.size>limit||!Number.isSafeInteger(limit)||limit<20||limit>16*1024*1024)deny('GLB_FILE_SIZE');
 if(typeof file.name!=='string'||!/\.glb$/i.test(file.name)||file.name.length>255)deny('GLB_FILE_EXTENSION');
 const bytes=await file.arrayBuffer();
 if(!(bytes instanceof ArrayBuffer)||bytes.byteLength!==file.size||bytes.byteLength>limit)deny('GLB_FILE_READ_INCONSISTENT');
 validateLocalGlbHeader(bytes);
 return bytes;
}
