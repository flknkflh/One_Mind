(function (global) {
  "use strict";

  const subtle = global.crypto && global.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const MASK_64 = (1n << 64n) - 1n;
  const PROTOCOL = "ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE";
  const PROTOCOL_VERSION = 5;
  const ENVELOPE_VERSION = "ONE_MIND-DIPP-EPHEMERAL-R-WEIGHTED-E2048-R10S12S-Q2500K-v5";
  const VAULT_TYPE = "ONE_MIND_DIPP_EPHEMERAL_R_IDENTITY";
  const VAULT_VERSION = 11;
  const GEOMETRY_PROFILE = "FIXED-WEISZFELD-24-WEIGHTED-8-R10S12S";
  const KEY_ESTABLISHMENT = "DIPP-ER-WEIGHTED-E2048-R10S12S-Q2500K-v5";
  const PARAMS = Object.freeze({
    id: "ER-DIPP-64-16-W8-E2048-R10S12S-Q2500K-v5",
    dimension: 64,
    publicPointCount: 16,
    coordinateRange: 1000000,
    fixedPointScale: 1000000,
    secretPointWeight: 8,
    secretRadiusMinPermille: 10000,
    secretRadiusMaxPermille: 12000,
    geometricNoiseNumerator: 0,
    geometricNoiseDenominator: 100,
    modulus: 65536,
    quantizationScale: 2500000,
    integerNoiseBound: 2048,
    preKeyBits: 256,
    maxCoordinateAbs: 34000000,
    solverIterations: 24,
  });
  const WEIGHT_SCALE = 1n << 52n;

  function requireCrypto() {
    if (!subtle || !global.crypto.getRandomValues) throw new Error("Web Crypto API diperlukan oleh Ephemeral-R DIPP.");
  }

  function utf8(value) { return enc.encode(String(value)); }

  function concatBytes(...parts) {
    const arrays = parts.map((part) => part instanceof Uint8Array ? part : new Uint8Array(part));
    const out = new Uint8Array(arrays.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of arrays) { out.set(part, offset); offset += part.length; }
    return out;
  }

  function bytesToBase64(bytes) {
    if (typeof global.btoa === "function") {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return global.btoa(binary);
    }
    return global.Buffer.from(bytes).toString("base64");
  }

  function base64ToBytes(text) {
    if (typeof text !== "string") throw new Error("Base64 harus string.");
    if (typeof global.atob === "function") {
      const binary = global.atob(text);
      return Uint8Array.from(binary, (char) => char.charCodeAt(0));
    }
    return new Uint8Array(global.Buffer.from(text, "base64"));
  }

  function b64url(bytes) { return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }

  function fromB64url(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("Base64url DIPP tidak canonical.");
    const bytes = base64ToBytes(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4));
    if (b64url(bytes) !== text) throw new Error("Base64url DIPP tidak canonical.");
    return bytes;
  }

  function bytesToHex(bytes) { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""); }

  function canonicalize(value) {
    if (value === null || typeof value === "boolean" || typeof value === "string") return value;
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) throw new Error("Canonical DIPP hanya menerima safe integer.");
      return value;
    }
    if (Array.isArray(value)) return value.map(canonicalize);
    if (typeof value === "object") {
      const result = {};
      for (const key of Object.keys(value).sort()) if (value[key] !== undefined) result[key] = canonicalize(value[key]);
      return result;
    }
    throw new Error("Tipe canonical DIPP tidak didukung.");
  }

  function encodeCanonical(value) { return utf8(JSON.stringify(canonicalize(value))); }
  function hasExactKeys(value, required) {
    return Boolean(value)
      && typeof value === "object"
      && !Array.isArray(value)
      && Object.keys(value).length === required.length
      && required.every(key => Object.prototype.hasOwnProperty.call(value, key));
  }
  function validUsername(value) { return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$/.test(value); }
  function validIsoTimestamp(value) {
    if (typeof value !== "string" || value.length > 64) return false;
    const parsed = new Date(value);
    return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
  }
  async function sha256(data) { requireCrypto(); return new Uint8Array(await subtle.digest("SHA-256", data)); }

  async function hkdf(ikm, salt, info, length = 32) {
    const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await subtle.deriveBits({name: "HKDF", hash: "SHA-256", salt, info}, key, length * 8));
  }

  function equalBytes(left, right) {
    if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) return false;
    let mismatch = left.length ^ right.length;
    const count = Math.max(left.length, right.length);
    for (let i = 0; i < count; i++) mismatch |= (left[i % Math.max(1, left.length)] || 0) ^ (right[i % Math.max(1, right.length)] || 0);
    return mismatch === 0;
  }

  const KECCAK_RC = [
    0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,
    0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
    0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,
    0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
    0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,
    0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n,
  ];
  const KECCAK_ROT = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
  function rotl64(value, shift) { const n=BigInt(shift); return n===0n?value&MASK_64:((value<<n)|(value>>(64n-n)))&MASK_64; }
  function keccakF(state) {
    for (const rc of KECCAK_RC) {
      const c=Array(5),d=Array(5),b=Array(25).fill(0n);
      for(let x=0;x<5;x++) c[x]=state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20];
      for(let x=0;x<5;x++) d[x]=c[(x+4)%5]^rotl64(c[(x+1)%5],1);
      for(let x=0;x<5;x++) for(let y=0;y<5;y++) state[x+5*y]=(state[x+5*y]^d[x])&MASK_64;
      for(let x=0;x<5;x++) for(let y=0;y<5;y++) b[y+5*((2*x+3*y)%5)]=rotl64(state[x+5*y],KECCAK_ROT[x+5*y]);
      for(let x=0;x<5;x++) for(let y=0;y<5;y++) state[x+5*y]=(b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]))&MASK_64;
      state[0]^=rc;
    }
  }
  function shake256(input, outputLength) {
    const rate=136,state=Array(25).fill(0n); let offset=0;
    while(offset+rate<=input.length){for(let i=0;i<rate;i++)state[Math.floor(i/8)]^=BigInt(input[offset+i])<<BigInt((i%8)*8);keccakF(state);offset+=rate;}
    const block=new Uint8Array(rate);block.set(input.slice(offset));block[input.length-offset]^=0x1f;block[rate-1]^=0x80;
    for(let i=0;i<rate;i++)state[Math.floor(i/8)]^=BigInt(block[i])<<BigInt((i%8)*8);keccakF(state);
    const out=new Uint8Array(outputLength);let written=0;
    while(written<outputLength){for(let i=0;i<rate&&written<outputLength;i++)out[written++]=Number((state[Math.floor(i/8)]>>BigInt((i%8)*8))&0xffn);if(written<outputLength)keccakF(state);}
    return out;
  }

  function readU32BE(bytes, offset) { return (((bytes[offset]<<24)>>>0)|(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3])>>>0; }
  function shakeSample(seed, count, range) {
    const limit=Math.floor(0x100000000/range)*range,values=[];let round=0;
    while(values.length<count){const stream=shake256(concatBytes(seed,encodeCanonical({round:round++})),Math.max(136,count*8));for(let o=0;o+4<=stream.length&&values.length<count;o+=4){const x=readU32BE(stream,o);if(x<limit)values.push(x%range);}}
    return values;
  }

  function randomU32() { const value=new Uint32Array(1);global.crypto.getRandomValues(value);return value[0]; }
  function randomInt(min,max){const range=max-min+1,limit=Math.floor(0x100000000/range)*range;let value;do{value=randomU32();}while(value>=limit);return min+(value%range);}
  function randomBytes(length){return global.crypto.getRandomValues(new Uint8Array(length));}

  function bigintSqrt(value){if(value<0n)throw new Error("Akar negatif.");if(value<2n)return value;let x=1n<<BigInt(Math.ceil(value.toString(2).length/2));for(;;){const next=(x+value/x)>>1n;if(next>=x)return x;x=next;}}
  function divRoundSigned(n,d){if(d<=0n)throw new Error("Pembagi fixed-point tidak valid.");return n>=0n?(n+d/2n)/d:-((-n+d/2n)/d);}

  function derivePublicPoints(seed, params=PARAMS){
    const values=shakeSample(concatBytes(utf8("DIPP-ER-PUBLIC-POINTS-v1"),seed),params.dimension*params.publicPointCount,2*params.coordinateRange+1);
    const points=[];for(let row=0;row<params.publicPointCount;row++)points.push(values.slice(row*params.dimension,(row+1)*params.dimension).map(v=>v-params.coordinateRange));return points;
  }

  function geometricMedian(points, params=PARAMS){
    if(!Array.isArray(points)||!points.length||points.some(p=>!Array.isArray(p)||p.length!==params.dimension))throw new Error("Point cloud Ephemeral-R tidak valid.");
    let center=Array(params.dimension).fill(0n);
    for(const point of points)for(let axis=0;axis<params.dimension;axis++)center[axis]+=BigInt(point[axis]);
    center=center.map(v=>divRoundSigned(v,BigInt(points.length)));
    for(let iteration=0;iteration<params.solverIterations;iteration++){
      const numerator=Array(params.dimension).fill(0n);let denominator=0n,singular=null;
      for(const point of points){let squared=0n;for(let axis=0;axis<params.dimension;axis++){const delta=center[axis]-BigInt(point[axis]);squared+=delta*delta;}
        if(squared===0n){singular=point.map(value=>BigInt(value));break;}const distance=bigintSqrt(squared)||1n;const weight=WEIGHT_SCALE/distance||1n;denominator+=weight;for(let axis=0;axis<params.dimension;axis++)numerator[axis]+=BigInt(point[axis])*weight;}
      center=singular||numerator.map(v=>divRoundSigned(v,denominator));
    }
    return center.map(Number);
  }

  function distanceInt(left,right){let squared=0n;for(let i=0;i<left.length;i++){const d=BigInt(left[i])-BigInt(right[i]);squared+=d*d;}return bigintSqrt(squared);}
  function publicScale(points,center){let squared=0n;for(const point of points){let item=0n;for(let i=0;i<point.length;i++){const d=BigInt(point[i])-BigInt(center[i]);item+=d*d;}squared+=item;}return bigintSqrt(divRoundSigned(squared,BigInt(points.length)))||1n;}

  function randomDirection(dimension){const out=[];for(let i=0;i<dimension;i++)out.push(BigInt(randomInt(-0x3fffffff,0x3fffffff)));return out;}
  function pointAtRadius(center,radius,params=PARAMS){
    let direction,norm;do{direction=randomDirection(params.dimension);norm=bigintSqrt(direction.reduce((sum,v)=>sum+v*v,0n));}while(norm===0n);
    return center.map((value,index)=>Number(BigInt(value)+divRoundSigned(direction[index]*radius,norm)));
  }
  function secretPoint(center,scaleValue,params=PARAMS){
    let point;
    do{
      const ratio=randomInt(params.secretRadiusMinPermille,params.secretRadiusMaxPermille);
      point=pointAtRadius(center,scaleValue*BigInt(ratio)/1000n,params);
    }while(point.some(value=>Math.abs(value)>params.maxCoordinateAbs));
    return point;
  }
  function weightedPoint(point,params=PARAMS){return Array.from({length:params.secretPointWeight},()=>point);}
  function boundedNoise(radius,params=PARAMS){if(radius<=0n)return Array(params.dimension).fill(0);const sampled=BigInt(randomU32())*radius/0xffffffffn;return pointAtRadius(Array(params.dimension).fill(0),sampled,params);}

  function normalizedFunctionalQuantized(center,points,scaleValue,params=PARAMS){const sum=points.reduce((total,point)=>total+distanceInt(center,point),0n);return Number(divRoundSigned(BigInt(params.quantizationScale)*sum,BigInt(points.length)*scaleValue)%BigInt(params.modulus));}
  function mod(value,modulus=PARAMS.modulus){const result=value%modulus;return result<0?result+modulus:result;}

  function encodeSignedVector(vector,params=PARAMS){if(!Array.isArray(vector)||vector.length!==params.dimension)throw new Error("Dimensi vector Ephemeral-R salah.");const out=new Uint8Array(vector.length*4);vector.forEach((value,index)=>{if(!Number.isSafeInteger(value)||value<-2147483648||value>2147483647)throw new Error("Coordinate Ephemeral-R di luar int32.");const unsigned=value>>>0;out[index*4]=(unsigned>>>24)&255;out[index*4+1]=(unsigned>>>16)&255;out[index*4+2]=(unsigned>>>8)&255;out[index*4+3]=unsigned&255;});return out;}
  function decodeSignedVector(encoded,params=PARAMS){const bytes=typeof encoded==="string"?fromB64url(encoded):encoded;if(bytes.length!==params.dimension*4)throw new Error("Panjang vector Ephemeral-R salah.");const vector=[];for(let o=0;o<bytes.length;o+=4){const u=readU32BE(bytes,o),value=u>0x7fffffff?u-0x100000000:u;if(Math.abs(value)>params.maxCoordinateAbs)throw new Error("Coordinate Ephemeral-R berada di luar domain profile.");vector.push(value);}if(typeof encoded==="string"&&b64url(encodeSignedVector(vector,params))!==encoded)throw new Error("Vector Ephemeral-R tidak canonical.");return vector;}

  function bitsFromBytes(bytes){const bits=[];for(const byte of bytes)for(let bit=7;bit>=0;bit--)bits.push((byte>>bit)&1);return bits;}
  function bytesFromBits(bits){if(bits.length!==PARAMS.preKeyBits||bits.length%8)throw new Error("Jumlah bit pre-key tidak valid.");const out=new Uint8Array(bits.length/8);for(let i=0;i<bits.length;i++){out[Math.floor(i/8)]|=bits[i]<<(7-(i%8));}return out;}

  function validatePublicKey(publicKey,expectedUser=null){
    const required=["protocol","version","type","user_id","key_id","parameter_profile","public_seed","B_b"];
    if(!hasExactKeys(publicKey,required)||publicKey.protocol!==PROTOCOL||publicKey.version!==PROTOCOL_VERSION||publicKey.type!=="ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE_PUBLIC"||publicKey.parameter_profile!==PARAMS.id||!validUsername(publicKey.user_id))throw new Error("Public key bukan Ephemeral-R DIPP standalone v5.");
    if(expectedUser&&publicKey.user_id!==expectedUser)throw new Error("Public key Ephemeral-R milik user berbeda.");
    if(fromB64url(publicKey.public_seed).length!==32||fromB64url(publicKey.B_b).length!==PARAMS.dimension*4||!/^[0-9a-f]{64}$/.test(publicKey.key_id))throw new Error("Public key Ephemeral-R tidak canonical.");
    decodeSignedVector(publicKey.B_b);
  }

  async function generateBobMaterial(username){
    const publicSeed=randomBytes(32),points=derivePublicPoints(publicSeed),center=geometricMedian(points),scaleValue=publicScale(points,center);
    const xB=secretPoint(center,scaleValue);
    const pB=geometricMedian(points.concat(weightedPoint(xB)));
    const noiseRadius=scaleValue*BigInt(PARAMS.geometricNoiseNumerator)/BigInt(PARAMS.geometricNoiseDenominator);
    const eta=boundedNoise(noiseRadius),bB=pB.map((v,i)=>v+eta[i]);
    const keyId=bytesToHex(await sha256(concatBytes(utf8("DIPP-ER-WEIGHTED-E2048-R10S12S-Q2500K-KEY-ID-v5"),utf8(username),publicSeed,encodeSignedVector(bB))));
    eta.fill(0);
    return {publicSeed,xB,bB,keyId};
  }

  async function generateIdentity(username,password){
    requireCrypto();if(!username||!password)throw new Error("Username dan password diperlukan.");
    const bob=await generateBobMaterial(username);
    const runtime={
      public:{protocol:PROTOCOL,version:PROTOCOL_VERSION,type:"ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE_PUBLIC",user_id:username,key_id:bob.keyId,parameter_profile:PARAMS.id,public_seed:b64url(bob.publicSeed),B_b:b64url(encodeSignedVector(bob.bB))},
      private:{bob_private_point:b64url(encodeSignedVector(bob.xB))},
      username,createdAt:new Date().toISOString(),vaultKey:null,kdf:null,
    };
    runtime.sealed=await sealIdentity(runtime,password);bob.xB.fill(0);return runtime;
  }

  async function deriveVaultKey(password,salt,iterations){const imported=await subtle.importKey("raw",utf8(password),"PBKDF2",false,["deriveKey"]);return subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt,iterations},imported,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);}
  async function sealIdentity(runtime,password=null){
    let key=runtime.vaultKey,kdf=runtime.kdf;if(!key){const salt=randomBytes(16);kdf={name:"PBKDF2-SHA-256",iterations:600000,salt:b64url(salt)};key=await deriveVaultKey(password,salt,kdf.iterations);runtime.vaultKey=key;runtime.kdf=kdf;}
    const iv=randomBytes(12),header={version:VAULT_VERSION,type:VAULT_TYPE,user_id:runtime.username,created_at:runtime.createdAt,public_key:runtime.public,kdf};
    const ciphertext=new Uint8Array(await subtle.encrypt({name:"AES-GCM",iv,additionalData:encodeCanonical(header)},key,encodeCanonical(runtime.private)));
    return runtime.sealed={...header,vault:{algorithm:"AES-256-GCM",nonce:b64url(iv),ciphertext:b64url(ciphertext)}};
  }
  async function openIdentity(packageValue,username,password){
    const required=["version","type","user_id","created_at","public_key","kdf","vault"];
    if(!hasExactKeys(packageValue,required)||packageValue.type!==VAULT_TYPE||packageValue.version!==VAULT_VERSION||!validUsername(packageValue.user_id)||!validIsoTimestamp(packageValue.created_at))throw new Error("Vault DIPP lama ditolak; gunakan Ephemeral-R weighted E2048 R10S12S Q2500K vault v11.");
    if(packageValue.user_id!==username)throw new Error("Vault DIPP milik user berbeda.");validatePublicKey(packageValue.public_key,username);
    if(!hasExactKeys(packageValue.kdf,["name","iterations","salt"])||!hasExactKeys(packageValue.vault,["algorithm","nonce","ciphertext"])||packageValue.kdf.name!=="PBKDF2-SHA-256"||!Number.isSafeInteger(packageValue.kdf.iterations)||packageValue.kdf.iterations!==600000||fromB64url(packageValue.kdf.salt).length!==16||packageValue.vault.algorithm!=="AES-256-GCM"||fromB64url(packageValue.vault.nonce).length!==12||fromB64url(packageValue.vault.ciphertext).length<17)throw new Error("Parameter vault tidak valid.");
    const header={version:packageValue.version,type:packageValue.type,user_id:packageValue.user_id,created_at:packageValue.created_at,public_key:packageValue.public_key,kdf:packageValue.kdf};
    const key=await deriveVaultKey(password,fromB64url(packageValue.kdf.salt),packageValue.kdf.iterations);let plaintext;
    try{plaintext=await subtle.decrypt({name:"AES-GCM",iv:fromB64url(packageValue.vault.nonce),additionalData:encodeCanonical(header)},key,fromB64url(packageValue.vault.ciphertext));}catch(error){throw new Error("Password salah atau vault Ephemeral-R berubah.");}
    const privateState=JSON.parse(dec.decode(plaintext));if(!hasExactKeys(privateState,["bob_private_point"])||!privateState.bob_private_point)throw new Error("Private state Ephemeral-R tidak lengkap.");decodeSignedVector(privateState.bob_private_point);
    return {public:packageValue.public_key,private:privateState,username,createdAt:packageValue.created_at,vaultKey:key,kdf:packageValue.kdf,sealed:packageValue};
  }

  function transcriptObject(publicKey,components,metadata){return {version:ENVELOPE_VERSION,parameter_profile:PARAMS.id,sender_id:metadata.sender_id,recipient_id:metadata.recipient_id,recipient_key_id:publicKey.key_id,public_seed:publicKey.public_seed,B_b:publicKey.B_b,session_id:metadata.session_id,file_context_id:metadata.file_context_id,dipp_components:components,algorithms:{geometry:GEOMETRY_PROFILE,extractor:"HKDF-SHA-256",key_establishment:KEY_ESTABLISHMENT}};}

  async function encapsulate(publicKey,metadata){
    validatePublicKey(publicKey,metadata.recipient_id);const seed=fromB64url(publicKey.public_seed),points=derivePublicPoints(seed),center=geometricMedian(points),scaleValue=publicScale(points,center),bB=decodeSignedVector(publicKey.B_b);
    const preKey=randomBytes(32),bits=bitsFromBytes(preKey),components=[],noiseRadius=scaleValue*BigInt(PARAMS.geometricNoiseNumerator)/BigInt(PARAMS.geometricNoiseDenominator);
    for(const bit of bits){const r=secretPoint(center,scaleValue),p=geometricMedian(points.concat(weightedPoint(r))),eta=boundedNoise(noiseRadius),u=p.map((v,i)=>v+eta[i]),cross=geometricMedian(points.concat(weightedPoint(r),weightedPoint(bB))),k=normalizedFunctionalQuantized(cross,points,scaleValue),e=randomInt(-PARAMS.integerNoiseBound,PARAMS.integerNoiseBound),v=mod(k+bit*(PARAMS.modulus/2)+e);components.push({U:b64url(encodeSignedVector(u)),V:v});r.fill(0);p.fill(0);eta.fill(0);cross.fill(0);}
    const transcript=transcriptObject(publicKey,components,metadata),transcriptHash=await sha256(encodeCanonical(transcript));
    const dippKey=await hkdf(preKey,transcriptHash,utf8(ENVELOPE_VERSION),32);preKey.fill(0);
    return {components,transcript,transcriptHash,dippKey};
  }

  async function decapsulateInternal(runtime,wrapped){
    validateEnvelope(wrapped);validatePublicKey(runtime.public,runtime.username);
    if(wrapped.recipient_id!==runtime.username||wrapped.recipient_key_id!==runtime.public.key_id)throw new Error("Ciphertext Ephemeral-R bukan untuk key penerima aktif.");
    const transcript=transcriptObject(runtime.public,wrapped.dipp_components,wrapped),hash=await sha256(encodeCanonical(transcript));if(wrapped.transcript_hash!==b64url(hash))throw new Error("Transcript Ephemeral-R berubah.");
    const points=derivePublicPoints(fromB64url(runtime.public.public_seed)),center=geometricMedian(points),scaleValue=publicScale(points,center),xB=decodeSignedVector(runtime.private.bob_private_point),bits=[];
    for(const component of wrapped.dipp_components){const u=decodeSignedVector(component.U),cross=geometricMedian(points.concat(weightedPoint(xB),weightedPoint(u))),k=normalizedFunctionalQuantized(cross,points,scaleValue),residual=mod(component.V-k),d0=Math.min(residual,PARAMS.modulus-residual),half=PARAMS.modulus/2,d1=Math.abs(residual-half);bits.push(d1<d0?1:0);cross.fill(0);u.fill(0);}
    const preKey=bytesFromBits(bits),dippKey=await hkdf(preKey,hash,utf8(ENVELOPE_VERSION),32);preKey.fill(0);xB.fill(0);return {dippKey,transcriptHash:hash};
  }

  function validateEnvelope(value){
    const required=["version","parameter_profile","sender_id","recipient_id","recipient_key_id","public_seed","B_b","session_id","file_context_id","dipp_components","algorithms","transcript_hash","key_establishment_algorithm","wrap_algorithm","wrap_nonce","wrapped_file_key","sender_signature_algorithm","sender_signature"];
    if(!value||typeof value!=="object"||Object.keys(value).length!==required.length||required.some(field=>!Object.prototype.hasOwnProperty.call(value,field)))throw new Error("Schema envelope Ephemeral-R tidak canonical.");
    if(!value||typeof value!=="object"||value.version!==ENVELOPE_VERSION||value.parameter_profile!==PARAMS.id||value.key_establishment_algorithm!==KEY_ESTABLISHMENT||value.wrap_algorithm!=="AES-256-GCM")throw new Error("Wrapped key bukan Ephemeral-R DIPP weighted E2048 R10S12S Q2500K v5.");
    if(!Array.isArray(value.dipp_components)||value.dipp_components.length!==PARAMS.preKeyBits)throw new Error("Jumlah component Ephemeral-R harus 256.");
    const seen=new Set();for(const component of value.dipp_components){if(!component||!Number.isSafeInteger(component.V)||component.V<0||component.V>=PARAMS.modulus)throw new Error("V_i Ephemeral-R di luar Z_q.");decodeSignedVector(component.U);const fingerprint=`${component.U}:${component.V}`;if(seen.has(fingerprint))throw new Error("Ciphertext component Ephemeral-R duplikat.");seen.add(fingerprint);}
    for(const field of ["sender_id","recipient_id","recipient_key_id","public_seed","B_b","session_id","file_context_id","transcript_hash","wrap_nonce","wrapped_file_key","sender_signature"]){if(typeof value[field]!=="string"||!value[field])throw new Error(`Field ${field} Ephemeral-R tidak valid.`);}
    if(!validUsername(value.sender_id)||!validUsername(value.recipient_id)||fromB64url(value.session_id).length!==24||fromB64url(value.file_context_id).length!==24)throw new Error("Binding identity/session Ephemeral-R tidak canonical.");
    if(value.sender_signature_algorithm!=="RSA-PKCS1-v1_5-SHA512"||value.algorithms?.geometry!==GEOMETRY_PROFILE||value.algorithms?.extractor!=="HKDF-SHA-256"||value.algorithms?.key_establishment!==KEY_ESTABLISHMENT||Object.keys(value.algorithms).length!==3)throw new Error("Suite algoritme Ephemeral-R tidak valid.");
    if(!/^[0-9a-f]{64}$/.test(value.recipient_key_id)||fromB64url(value.public_seed).length!==32)throw new Error("Public binding Ephemeral-R tidak valid.");decodeSignedVector(value.B_b);
    if(fromB64url(value.transcript_hash).length!==32||fromB64url(value.wrap_nonce).length!==12||fromB64url(value.wrapped_file_key).length!==48||fromB64url(value.sender_signature).length!==512)throw new Error("Encoding envelope Ephemeral-R tidak valid.");
  }

  async function decapsulate(runtime,wrapped){try{return await decapsulateInternal(runtime,wrapped);}catch(error){throw new Error("Decapsulation Ephemeral-R gagal.");}}
  async function wrapFileKey(recipientPublic,rawFileKey,metadata,signer){
    if(!(rawFileKey instanceof Uint8Array)||rawFileKey.length!==32)throw new Error("AES file key wajib tepat 256 bit.");
    const sessionId=b64url(randomBytes(24)),er=await encapsulate(recipientPublic,{...metadata,session_id:sessionId}),key=await subtle.importKey("raw",er.dippKey,{name:"AES-GCM"},false,["encrypt"]),nonce=randomBytes(12);
    const aad=encodeCanonical({version:ENVELOPE_VERSION,session_id:sessionId,file_context_id:metadata.file_context_id,sender_id:metadata.sender_id,recipient_id:metadata.recipient_id,transcript_hash:b64url(er.transcriptHash)});
    const ciphertext=new Uint8Array(await subtle.encrypt({name:"AES-GCM",iv:nonce,additionalData:aad},key,rawFileKey)),signature=await signer(er.transcriptHash);
    er.dippKey.fill(0);
    return {...er.transcript,transcript_hash:b64url(er.transcriptHash),key_establishment_algorithm:KEY_ESTABLISHMENT,wrap_algorithm:"AES-256-GCM",wrap_nonce:b64url(nonce),wrapped_file_key:b64url(ciphertext),sender_signature_algorithm:"RSA-PKCS1-v1_5-SHA512",sender_signature:b64url(signature)};
  }
  async function unwrapFileKeyInternal(runtime,wrapped,signatureVerifier){
    validateEnvelope(wrapped);const hash=fromB64url(wrapped.transcript_hash);if(!await signatureVerifier(hash,fromB64url(wrapped.sender_signature),wrapped.sender_id))throw new Error("Signature transcript Ephemeral-R tidak valid.");
    let er,key;try{er=await decapsulateInternal(runtime,wrapped);key=await subtle.importKey("raw",er.dippKey,{name:"AES-GCM"},false,["decrypt"]);}catch(error){throw new Error("Decapsulation Ephemeral-R gagal.");}
    const aad=encodeCanonical({version:ENVELOPE_VERSION,session_id:wrapped.session_id,file_context_id:wrapped.file_context_id,sender_id:wrapped.sender_id,recipient_id:wrapped.recipient_id,transcript_hash:wrapped.transcript_hash});let plaintext;
    try{plaintext=new Uint8Array(await subtle.decrypt({name:"AES-GCM",iv:fromB64url(wrapped.wrap_nonce),additionalData:aad},key,fromB64url(wrapped.wrapped_file_key)));}catch(error){throw new Error("Authentication tag wrapped key gagal.");}
    er.dippKey.fill(0);return plaintext;
  }
  async function unwrapFileKey(runtime,wrapped,signatureVerifier){try{return await unwrapFileKeyInternal(runtime,wrapped,signatureVerifier);}catch(error){throw new Error("Decapsulation Ephemeral-R gagal.");}}

  global.OneMindDippEphemeralR=Object.freeze({PROTOCOL,PROTOCOL_VERSION,ENVELOPE_VERSION,VAULT_TYPE,VAULT_VERSION,PARAMS,utf8,concatBytes,b64url,fromB64url,bytesToHex,encodeCanonical,sha256,hkdf,equalBytes,shake256,derivePublicPoints,geometricMedian,publicScale,encodeSignedVector,decodeSignedVector,validatePublicKey,validateEnvelope,generateIdentity,sealIdentity,openIdentity,transcriptObject,encapsulate,decapsulate,wrapFileKey,unwrapFileKey});
})(typeof globalThis!=="undefined"?globalThis:window);
