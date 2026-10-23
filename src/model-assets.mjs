/**
 * Safe-subset glTF 2.0 GLB inspector + CPU preview mesh adapter.
 * Independent of Node and UI. Importing never confers manufacturing approval.
 * Scope: embedded BIN, TRIANGLES, POSITION (float32 VEC3), TEXCOORD_0
 * (float32 VEC2), optional unsigned-short/unsigned-int indices. Scene nodes
 * may use standard matrix or TRS; extensions, skinning, morphs, draco, external
 * buffers and untrusted textures are rejected, not interpreted.
 */
const MAX_BYTES=16*1024*1024, MAX_VERTICES=140000, MAX_TRIANGLES=45000, MAX_NODES=250;
const reject=(code,why)=>{const e=new Error(why);e.code=code;throw e;};
const finite=n=>typeof n==='number'&&Number.isFinite(n);
const bytesOf=v=>v instanceof ArrayBuffer?new Uint8Array(v):v instanceof Uint8Array?v:new Uint8Array(v.buffer,v.byteOffset,v.byteLength);
const utf8=new TextDecoder('utf-8',{fatal:true});
const unit=n=>finite(n)&&n>=0&&n<=1;
const ident=()=>[1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1];
function mul(a,b){const o=new Array(16).fill(0);for(let c=0;c<4;c++)for(let r=0;r<4;r++)for(let k=0;k<4;k++)o[c*4+r]+=a[k*4+r]*b[c*4+k];return o;}
function trs(node){
 if(node.matrix!==undefined){if(!Array.isArray(node.matrix)||node.matrix.length!==16||!node.matrix.every(finite))reject('MATRIX','Invalid node matrix');return node.matrix;}
 const t=node.translation??[0,0,0],s=node.scale??[1,1,1],q=node.rotation??[0,0,0,1];
 if(t.length!==3||s.length!==3||q.length!==4||![...t,...s,...q].every(finite))reject('TRS','Invalid node transform');
 if(s.some(x=>x===0))reject('TRS','Zero-scale geometry cannot be rendered');
 const norm=Math.hypot(...q);if(norm<1e-8)reject('TRS','Zero quaternion');
 const [x,y,z,w]=q.map(v=>v/norm),x2=x+x,y2=y+y,z2=z+z;
 const xx=x*x2,xy=x*y2,xz=x*z2,yy=y*y2,yz=y*z2,zz=z*z2,wx=w*x2,wy=w*y2,wz=w*z2;
 return [(1-(yy+zz))*s[0],(xy+wz)*s[0],(xz-wy)*s[0],0,(xy-wz)*s[1],(1-(xx+zz))*s[1],(yz+wx)*s[1],0,(xz+wy)*s[2],(yz-wx)*s[2],(1-(xx+yy))*s[2],0,...t,1];
}
const transform=(m,p)=>[m[0]*p[0]+m[4]*p[1]+m[8]*p[2]+m[12],m[1]*p[0]+m[5]*p[1]+m[9]*p[2]+m[13],m[2]*p[0]+m[6]*p[1]+m[10]*p[2]+m[14]];
async function digest(raw){
 const subtle=globalThis.crypto?.subtle;
 if(!subtle||typeof subtle.digest!=='function')reject('GLB_SECURE_CONTEXT_REQUIRED','GLB SHA-256 needs WebCrypto on a secure browser origin');
 const hash=await subtle.digest('SHA-256',raw);
 if(!(hash instanceof ArrayBuffer)||hash.byteLength!==32)reject('GLB_DIGEST_INVALID','GLB digest failed validation');
 return [...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function parse(raw){
 const u=bytesOf(raw);
 if(u.length<20||u.length>MAX_BYTES)reject('FILE_SIZE','GLB must be 20 bytes to 16 MB');
 const view=new DataView(u.buffer,u.byteOffset,u.byteLength);
 if(view.getUint32(0,true)!==0x46546c67||view.getUint32(4,true)!==2||view.getUint32(8,true)!==u.length)reject('HEADER','Expected complete glTF 2.0 GLB header');
 let offset=12,doc=null,bin=null;
 while(offset<u.length){
  if(offset+8>u.length)reject('CHUNK','Truncated GLB chunk header');
  const size=view.getUint32(offset,true),type=view.getUint32(offset+4,true);offset+=8;
  if(size%4!==0||size>u.length-offset)reject('CHUNK','Invalid GLB chunk length');
  const data=u.subarray(offset,offset+size);offset+=size;
  if(type===0x4e4f534a){if(doc!==null||bin!==null)reject('CHUNK','JSON chunk must be first and unique');
   try{doc=JSON.parse(utf8.decode(data).trimEnd());}catch{reject('JSON','Invalid UTF-8 or JSON');}}
  else if(type===0x004e4942){if(bin!==null||doc===null)reject('CHUNK','Unexpected BIN chunk');bin=data;}
  else reject('CHUNK','Unsupported GLB chunk type');
 }
 if(doc?.asset?.version?.split('.')[0]!=='2'||!bin)reject('ASSET','Requires glTF 2.0 JSON and embedded BIN');
 if(doc.extensionsRequired?.length||doc.extensionsUsed?.length)reject('EXTENSIONS','Unsupported glTF extensions: convert to plain GLB');
 if(doc.buffers?.length!==1||doc.buffers[0].uri!==undefined||!Number.isSafeInteger(doc.buffers[0].byteLength)||doc.buffers[0].byteLength>bin.length||bin.length-doc.buffers[0].byteLength>3)reject('BUFFER','Exactly one embedded BIN buffer is supported');
 if(doc.images?.some(im=>im.uri)||doc.textures?.length||doc.images?.length)reject('TEXTURES','External and embedded textures disabled in asset preview');
 if(!Array.isArray(doc.nodes)||doc.nodes.length>MAX_NODES||!Array.isArray(doc.meshes)||!Array.isArray(doc.accessors)||!Array.isArray(doc.bufferViews))reject('STRUCTURE','Missing or excessive GLB structure');
 return {u,doc,bin};
}
function accessor(doc,bin,index,expected){
 const a=doc.accessors[index];if(!a||a.sparse||a.normalized||a.type!==expected||a.bufferView===undefined)reject('ACCESSOR','Unsupported accessor type or storage');
 const components=expected==='VEC3'?3:expected==='VEC2'?2:1;
 const allowed=expected==='SCALAR'?[5123,5125]:[5126];if(!allowed.includes(a.componentType))reject('ACCESSOR','Unsupported accessor component type');
 const size=a.componentType===5123?2:4,element=size*components;
 if(!Number.isInteger(a.count)||a.count<1||a.count>MAX_VERTICES)reject('ACCESSOR','Invalid accessor count');
 const bv=doc.bufferViews[a.bufferView];if(!bv||bv.buffer!==0||bv.target===34963&&expected!=='SCALAR')reject('BUFFERVIEW','Invalid buffer view');
 const base=(bv.byteOffset||0)+(a.byteOffset||0),stride=bv.byteStride||element;
 if(![base,stride,bv.byteLength,bv.byteOffset||0,a.byteOffset||0].every(Number.isSafeInteger)||base<0||stride<element||stride>255||stride%size||base%size)reject('BUFFERVIEW','Invalid offset or stride');
 if(base+(a.count-1)*stride+element>bin.length||(a.byteOffset||0)+(a.count-1)*stride+element>bv.byteLength)reject('BUFFERVIEW','Accessor overflows view');
 const dv=new DataView(bin.buffer,bin.byteOffset,bin.byteLength),out=[];
 for(let i=0;i<a.count;i++){
  const row=[];for(let k=0;k<components;k++){const o=base+i*stride+k*size;const v=a.componentType===5126?dv.getFloat32(o,true):a.componentType===5123?dv.getUint16(o,true):dv.getUint32(o,true);if(!finite(v))reject('NONFINITE','Nonfinite mesh coordinate');row.push(v);}
  out.push(components===1?row[0]:row);
 }
 return out;
}
/** Import an in-memory asset for one declared product family. NO implicit approval. */
export async function inspectGlb(raw,manifest){
 const {u,doc,bin}=parse(raw);const declared=new Set((manifest?.surfaces||[]).map(x=>x.id));
 if(!manifest?.geometry||!declared.size)reject('PRODUCT','Select a valid product before importing');
 const scene=doc.scenes?.[doc.scene??0];if(!scene||!Array.isArray(scene.nodes))reject('SCENE','Default glTF scene required');
 const triangles=[],used=new Set(),visited=new Set(),inStack=new Set(),bounds={min:[Infinity,Infinity,Infinity],max:[-Infinity,-Infinity,-Infinity]};
 let vertexCount=0;
 function traverse(nodeId,parent){
  const node=doc.nodes[nodeId];if(!node)reject('NODE','Missing scene node');
  if(inStack.has(nodeId)||visited.has(nodeId))reject('NODE','Cycles and duplicated scene nodes are unsupported');
  inStack.add(nodeId);visited.add(nodeId);
  if(node.skin!==undefined||node.weights!==undefined)reject('SKIN','Skinned meshes require an advanced renderer');
  const matrix=mul(parent,trs(node));
  if(node.mesh!==undefined){const mesh=doc.meshes[node.mesh];if(!mesh?.primitives?.length)reject('MESH','Invalid scene mesh');
   for(const primitive of mesh.primitives){
    if((primitive.mode??4)!==4||primitive.targets?.length)reject('PRIMITIVE','Only static TRIANGLES primitives supported');
    if(primitive.attributes?.POSITION===undefined)reject('PRIMITIVE','POSITION accessor required');
    const points=accessor(doc,bin,primitive.attributes.POSITION,'VEC3');vertexCount+=points.length;
    if(vertexCount>MAX_VERTICES)reject('LIMIT','Too many vertices for local viewer');
    const uv=primitive.attributes.TEXCOORD_0!==undefined?accessor(doc,bin,primitive.attributes.TEXCOORD_0,'VEC2'):null;
    if(uv&&uv.length!==points.length)reject('UV','UV count differs from position count');
    const surfaceId=primitive.extras?.tjSurfaceId??node.extras?.tjSurfaceId??null;
    if(surfaceId&&!declared.has(surfaceId))reject('SURFACE',`Asset surface ${surfaceId} not in selected product`);
    if(surfaceId&&!uv)reject('UV','Printable mesh surface requires UV coordinates');
    if(surfaceId)used.add(surfaceId);
    const indices=primitive.indices!==undefined?accessor(doc,bin,primitive.indices,'SCALAR'):points.map((_,i)=>i);
    if(indices.length%3)reject('INDICES','Triangle index count must be divisible by 3');
    for(let j=0;j<indices.length;j+=3){
     if(triangles.length>=MAX_TRIANGLES)reject('LIMIT','Too many triangles for local viewer');
     const ix=indices.slice(j,j+3);if(ix.some(k=>!Number.isInteger(k)||k<0||k>=points.length))reject('INDICES','Triangle references invalid vertex');
     const p=ix.map(k=>transform(matrix,points[k]));
     if(p.flat().some(x=>!finite(x)||Math.abs(x)>10000))reject('BOUNDS','Invalid transformed geometry');
     for(const vec of p)vec.forEach((x,k)=>{bounds.min[k]=Math.min(bounds.min[k],x);bounds.max[k]=Math.max(bounds.max[k],x);});
     const tri={a:p[0],b:p[1],c:p[2],material:'fabric',side:'asset',surfaceId:surfaceId||null};
     if(surfaceId){const tex=ix.map(k=>uv[k]);if(tex.flat().some(x=>!unit(x)))reject('UV','Printable UVs must be in normalized 0..1 atlas');tri.uv=tex;}
     triangles.push(tri);
    }
   }
  }
  for(const id of node.children||[])traverse(id,matrix);
  inStack.delete(nodeId);
 }
 for(const n of scene.nodes)traverse(n,ident());
 if(!triangles.length)reject('MESH','No renderable triangles');
 const size=bounds.max.map((x,k)=>x-bounds.min[k]);if(size.some(x=>!finite(x))||Math.max(...size)<=0)reject('BOUNDS','Degenerate model dimensions');
 const center=bounds.min.map((v,k)=>(v+bounds.max[k])/2), scale=2.6/Math.max(...size);
 const normalized=triangles.map(t=>({ ...t,a:t.a.map((v,k)=>(v-center[k])*scale),b:t.b.map((v,k)=>(v-center[k])*scale),c:t.c.map((v,k)=>(v-center[k])*scale) }));
 const sha256=await digest(u);
 return {
  sha256,byteLength:u.length,nodeCount:visited.size,vertexCount,triangleCount:triangles.length,
  assetBoundsMeters:{min:bounds.min,max:bounds.max,extent:size},
  mappedSurfaces:[...used].sort(),missingSurfaces:[...declared].filter(x=>!used.has(x)),
  asset:{modelId:`imported-${sha256.slice(0,14)}`,status:'IMPORTED_UNVERIFIED',triangles:normalized,surfaceIds:[...used],sha256},
  approval:'UNVERIFIED_LOCAL_PREVIEW_ONLY'
 };
}
