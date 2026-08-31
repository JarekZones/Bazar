const JSON_HEADERS={"Content-Type":"application/json; charset=utf-8"};
const FIELD_KEYS=["brand","color","memory","imei","note"];
const DEFAULT_FIELDS={brand:true,color:true,memory:false,imei:false,note:true};
const ELECTRONICS_FIELDS={brand:true,color:true,memory:true,imei:true,note:true};

export default {
  async fetch(request,env){
    const origin=env.ALLOWED_ORIGIN||"*";
    if(request.method==="OPTIONS")return new Response(null,{status:204,headers:corsHeaders(origin)});
    try{
      const url=new URL(request.url);
      if(url.pathname==="/api/auth"&&request.method==="POST")return await handleAuth(request,env,origin);
      if(url.pathname==="/api/contact"&&request.method==="POST")return await handleContact(request,env,origin);
      if(url.pathname==="/api/products"&&request.method==="GET"){
        const categories=(await getCategories(env)).map(normalizeCategory);
        const products=(await getGitHubData(env)).map(p=>normalizeProduct(p,categories));
        const activeCategoryIds=new Set(products.filter(p=>!p.sold).map(p=>p.category));
        const publicCategories=categories.filter(c=>c.visible&&activeCategoryIds.has(c.id));
        return json({products,categories:publicCategories},200,origin);
      }
      if(url.pathname==="/api/admin/data"&&request.method==="GET"){
        await requireAuth(request,env);
        return await handleAdminData(env,origin);
      }
      if(url.pathname==="/api/image"&&request.method==="POST"){
        await requireAuth(request,env);
        return await handleImageUpload(request,env,origin);
      }
      if(url.pathname==="/api/save"&&request.method==="POST"){
        await requireAuth(request,env);
        return await handleSave(request,env,origin);
      }
      return json({error:"Požadovaná stránka nebyla nalezena."},404,origin);
    }catch(error){
      console.error(error);
      const status=error instanceof HttpError?error.status:500;
      return json({error:error instanceof Error?error.message:"Interní chyba serveru."},status,origin);
    }
  }
};

function corsHeaders(origin){return{"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Headers":"Content-Type, Authorization","Access-Control-Allow-Methods":"GET, POST, OPTIONS","Vary":"Origin"}}
function json(data,status=200,origin="*"){return new Response(JSON.stringify(data),{status,headers:{...JSON_HEADERS,...corsHeaders(origin)}})}
class HttpError extends Error{constructor(message,status){super(message);this.status=status}}

async function handleAuth(request,env,origin){
  const body=await request.json().catch(()=>({}));
  const password=String(body.password||"");
  if(!env.ADMIN_PASSWORD||password!==env.ADMIN_PASSWORD)return json({error:"Neplatné heslo."},401,origin);
  const token=await createToken(env.SESSION_SECRET);
  return json({token,expiresIn:8*60*60},200,origin);
}
async function requireAuth(request,env){
  const header=request.headers.get("Authorization")||"";
  const token=header.startsWith("Bearer ")?header.slice(7):"";
  if(!token||!(await verifyToken(token,env.SESSION_SECRET)))throw new HttpError("Neplatné nebo prošlé přihlášení.",401);
}

async function handleContact(request,env,origin){
  if(!env.RESEND_API_KEY)throw new HttpError("Odesílání e-mailů není nastavené.",500);
  const body=await request.json().catch(()=>({}));
  const name=String(body.name||"").trim();
  const email=String(body.email||"").trim().toLowerCase();
  const message=String(body.message||"").trim();
  const productId=String(body.productId??"").trim();
  const website=String(body.website||"").trim();
  const startedAt=Number(body.startedAt||0);

  if(website)return json({ok:true,message:"Zpráva byla úspěšně odeslána."},200,origin);
  if(startedAt&&Date.now()-startedAt<1500)return json({error:"Formulář byl odeslán příliš rychle. Zkuste to prosím znovu."},429,origin);
  if(name.length<2||name.length>100)return json({error:"Zadejte prosím jméno."},400,origin);
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)return json({error:"Zadejte platnou e-mailovou adresu."},400,origin);
  if(message.length<3||message.length>4000)return json({error:"Zpráva musí mít 3 až 4000 znaků."},400,origin);
  if(!productId)return json({error:"Chybí vybraný produkt."},400,origin);

  if(env.IMEI_KV){
    const ip=request.headers.get("CF-Connecting-IP")||"unknown";
    const ipHash=await sha256Hex(ip);
    const bucket=Math.floor(Date.now()/3600000);
    const rateKey=`contact-rate:${ipHash}:${bucket}`;
    const count=Number(await env.IMEI_KV.get(rateKey)||0);
    if(count>=5)return json({error:"Bylo odesláno příliš mnoho zpráv. Zkuste to prosím později."},429,origin);
    await env.IMEI_KV.put(rateKey,String(count+1),{expirationTtl:7200});
  }

  const products=await getGitHubData(env);
  const product=products.find(p=>String(p.id)===productId&&!p.sold);
  if(!product)return json({error:"Produkt už není k dispozici."},404,origin);
  const title=String(product.title||"Produkt").trim().slice(0,160);
  const text=[
    `Zájem o produkt: ${title}`,
    `ID produktu: ${productId}`,
    "",
    `Jméno: ${name}`,
    `E-mail: ${email}`,
    "",
    "Zpráva:",
    message
  ].join("\n");

  const response=await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{
      "Authorization":`Bearer ${env.RESEND_API_KEY}`,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({
      from:"Soukromý bazárek <bazarek@mobilmax.cz>",
      to:["j.preclik@mobilmax.cz"],
      reply_to:email,
      subject:`Zájem o ${title}`,
      text
    })
  });
  if(!response.ok){
    const detail=await response.text();
    console.error("Resend error",response.status,detail.slice(0,1000));
    return json({error:"E-mail se nepodařilo odeslat. Zkuste to prosím znovu."},502,origin);
  }

  const confirmationText=[
    `Dobrý den${name?` ${name}`:""},`,
    "",
    `děkuji za zprávu ohledně produktu „${title}“.`,
    "Vaše zpráva byla úspěšně doručena.",
    "Ozvu se vám co nejdříve.",
    "",
    "S pozdravem",
    "Soukromý bazárek"
  ].join("\n");

  const confirmation=await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{
      "Authorization":`Bearer ${env.RESEND_API_KEY}`,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({
      from:"Soukromý bazárek <bazarek@mobilmax.cz>",
      to:[email],
      reply_to:"j.preclik@mobilmax.cz",
      subject:`Potvrzení přijetí zprávy – ${title}`,
      text:confirmationText
    })
  });
  if(!confirmation.ok){
    const detail=await confirmation.text();
    console.error("Resend confirmation error",confirmation.status,detail.slice(0,1000));
  }

  return json({ok:true,message:"Zpráva byla úspěšně odeslána."},200,origin);
}

function normalizeFeature(f){
  if(typeof f==="string"){const name=f.trim();return{id:slugify(name),name}}
  const name=String(f?.name||"").trim();
  const id=String(f?.id||slugify(name)).trim();
  return{id,name};
}
function normalizeFields(fields,id){
  const base=id==="electronics"?ELECTRONICS_FIELDS:DEFAULT_FIELDS;
  const result={};
  for(const key of FIELD_KEYS)result[key]=fields&&typeof fields[key]==="boolean"?fields[key]:base[key];
  return result;
}
function normalizeCategory(c){
  const id=String(c?.id||"").trim();
  const features=Array.isArray(c?.features)?c.features.map(normalizeFeature).filter(f=>f.id&&f.name):[];
  return{
    id,
    name:String(c?.name||"").trim(),
    image:typeof c?.image==="string"&&!c.image.startsWith("data:")?c.image.trim():"",
    visible:c?.visible!==false,
    fields:normalizeFields(c?.fields,id),
    features
  };
}
function normalizeProduct(product,categories=[]){
  const p={...product};
  p.category=String(p.category||"electronics");
  p.brand=String(p.brand||"").trim();
  p.color=String(p.color||"").trim();
  p.memory=String(p.memory||"").trim();
  p.note=String(p.note||"");
  p.condition=["regular","demo","new"].includes(p.condition)?p.condition:(p.demo?"demo":"regular");
  p.demo=p.condition==="demo";
  p.sold=!!p.sold;
  let features=Array.isArray(p.features)?p.features.map(String):[];
  if(!features.length&&p.category==="electronics"){
    [["charger",p.charger],["cable",p.cable],["earphones",p.earphones],["case",p.case],["box",p.box]].forEach(([id,on])=>{if(on)features.push(id)});
  }
  const allowed=new Set((categories.find(c=>c.id===p.category)?.features||[]).map(f=>f.id));
  p.features=[...new Set(features.filter(id=>!allowed.size||allowed.has(id)))];
  return p;
}

async function handleAdminData(env,origin){
  const categories=(await getCategories(env)).map(normalizeCategory);
  const products=(await getGitHubData(env)).map(p=>normalizeProduct(p,categories));
  let imeiMap={};
  if(env.IMEI_KV)imeiMap=(await env.IMEI_KV.get("imei-map","json"))||{};
  const result=products.map(product=>({...product,imei:imeiMap[String(product.id)]||""}));
  return json({products:result,categories},200,origin);
}

async function handleSave(request,env,origin){
  const body=await request.json().catch(()=>({}));
  const incoming=Array.isArray(body.products)?body.products:null;
  if(!incoming)return json({error:"Očekáváno pole products."},400,origin);
  const categories=(Array.isArray(body.categories)?body.categories:await getCategories(env)).map(normalizeCategory);
  validateCategories(categories);
  const normalized=incoming.map(p=>normalizeProduct(p,categories));
  validateProducts(normalized,categories);

  const imeiMap={};
  for(const product of normalized){
    const cat=categories.find(c=>c.id===product.category);
    const imei=cat?.fields?.imei?String(product.imei||"").replace(/\D/g,""):"";
    if(imei){
      if(!/^\d{15}$/.test(imei))return json({error:`Neplatné IMEI u produktu ${product.id}.`},400,origin);
      imeiMap[String(product.id)]=imei;
    }
  }
  const imeis=Object.values(imeiMap);
  if(new Set(imeis).size!==imeis.length)return json({error:"IMEI musí být jedinečné."},400,origin);

  const cleanProducts=normalized.map(product=>{
    const copy={...product};
    delete copy.imei;
    delete copy.charger;delete copy.cable;delete copy.earphones;delete copy.case;delete copy.box;
    const cleanImages=Array.isArray(copy.images)?copy.images.filter(image=>typeof image==="string"&&image.trim()&&!image.startsWith("data:")):[];
    const fallbackImg=typeof copy.img==="string"&&copy.img.trim()&&!copy.img.startsWith("data:")?copy.img.trim():"";
    copy.images=cleanImages.length?cleanImages:(fallbackImg?[fallbackImg]:[]);
    copy.img=copy.images[0]||"";
    return copy;
  });

  await putGitHubFile(env,"data.json",JSON.stringify(cleanProducts,null,2)+"\n",`Aktualizace katalogu ${new Date().toISOString()}`);
  await putGitHubFile(env,"categories.json",JSON.stringify(categories,null,2)+"\n",`Aktualizace kategorií ${new Date().toISOString()}`);

  if(!env.IMEI_KV)throw new HttpError("Není nastaven Cloudflare KV binding IMEI_KV.",500);
  await env.IMEI_KV.put("imei-map",JSON.stringify(imeiMap));
  const result=cleanProducts.map(product=>({...product,imei:imeiMap[String(product.id)]||""}));
  return json({ok:true,products:result,categories},200,origin);
}

async function handleImageUpload(request,env,origin){
  const body=await request.json().catch(()=>({}));
  const filename=sanitizeFilename(body.filename||"");
  const data=String(body.data||"");
  if(!filename||!data.startsWith("data:"))return json({error:"Neplatný obrázek."},400,origin);
  const match=data.match(/^data:([^;]+);base64,(.+)$/);
  if(!match)return json({error:"Neplatný formát obrázku."},400,origin);
  const mime=match[1],base64=match[2];
  if(!/^image\/(jpeg|jpg|png|webp)$/i.test(mime))return json({error:"Povolené jsou JPG, PNG a WebP."},400,origin);
  const binary=atob(base64),bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
  if(bytes.byteLength>8*1024*1024)return json({error:"Obrázek je příliš velký."},400,origin);
  let extension="jpg";if(mime.includes("png"))extension="png";if(mime.includes("webp"))extension="webp";
  const path=`images/${filename.replace(/\.[^.]+$/,"")}.${extension}`;
  const result=await putGitHubBytes(env,path,bytes,`Nahrání obrázku ${path}`);
  return json({ok:true,path,url:result.content?.download_url||`https://raw.githubusercontent.com/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/${env.GITHUB_BRANCH||"main"}/${path}`},200,origin);
}

async function getGitHubData(env){return await getJsonArray(env,"data.json",[])}
async function getCategories(env){return await getJsonArray(env,"categories.json",[{id:"electronics",name:"Elektronika",image:"",visible:true,fields:ELECTRONICS_FIELDS,features:[]}])}
async function getJsonArray(env,path,fallback){const file=await getGitHubFile(env,path);if(!file)return fallback;const data=JSON.parse(decodeBase64Utf8(file.content));if(!Array.isArray(data))throw new Error(`${path} nemá správný formát.`);return data}
async function getGitHubFile(env,path){const branch=env.GITHUB_BRANCH||"main";const url=`https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${encodePath(path)}?ref=${encodeURIComponent(branch)}`;const response=await githubFetch(env,url);if(response.status===404)return null;if(!response.ok){const text=await response.text();throw new Error(`GitHub GET ${path} selhal (${response.status}): ${text.slice(0,500)}`)}return await response.json()}
async function putGitHubFile(env,path,content,message){return await putGitHubBytes(env,path,new TextEncoder().encode(content),message)}
async function putGitHubBytes(env,path,bytes,message){const existing=await getGitHubFile(env,path);const body={message,content:bytesToBase64(bytes),branch:env.GITHUB_BRANCH||"main"};if(existing?.sha)body.sha=existing.sha;const response=await githubFetch(env,`https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${encodePath(path)}`,{method:"PUT",body:JSON.stringify(body)});if(!response.ok){const text=await response.text();throw new Error(`GitHub PUT ${path} selhal (${response.status}): ${text.slice(0,500)}`)}return await response.json()}
async function githubFetch(env,url,options={}){const headers=new Headers(options.headers||{});headers.set("Accept","application/vnd.github+json");headers.set("Authorization",`Bearer ${env.GITHUB_TOKEN}`);headers.set("X-GitHub-Api-Version","2022-11-28");headers.set("User-Agent","bazar-admin-worker");if(options.body)headers.set("Content-Type","application/json");return fetch(url,{...options,headers})}

function validateProducts(products,categories){
  const ids=new Set(),categoryIds=new Set(categories.map(c=>c.id));
  for(const product of products){
    if(!product||product.id===undefined||!product.title)throw new HttpError("Každý produkt musí mít ID a název.",400);
    const id=String(product.id);if(ids.has(id))throw new HttpError(`Duplicitní ID produktu: ${id}`,400);ids.add(id);
    if(!categoryIds.has(product.category))throw new HttpError(`Neplatná kategorie u produktu ${product.id}.`,400);
  }
}
function validateCategories(categories){
  if(!categories.length)throw new HttpError("Musí existovat alespoň jedna kategorie.",400);
  const ids=new Set();
  for(const c of categories){
    if(!c.id||!c.name)throw new HttpError("Každá kategorie musí mít ID a název.",400);
    if(ids.has(c.id))throw new HttpError(`Duplicitní ID kategorie: ${c.id}`,400);ids.add(c.id);
    for(const key of FIELD_KEYS)if(typeof c.fields?.[key]!=="boolean")throw new HttpError(`Neplatné nastavení polí v kategorii ${c.name}.`,400);
    const featureIds=new Set();
    for(const f of c.features){if(!f.id||!f.name)throw new HttpError(`Neplatná vlastnost v kategorii ${c.name}.`,400);if(featureIds.has(f.id))throw new HttpError(`Duplicitní vlastnost v kategorii ${c.name}: ${f.name}`,400);featureIds.add(f.id)}
  }
}

function slugify(s){return String(s||"").normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")}
function sanitizeFilename(value){return String(value).replace(/[^a-zA-Z0-9._-]+/g,"-").replace(/-+/g,"-").replace(/^\.+/,"").slice(0,140)}
function encodePath(path){return path.split("/").map(encodeURIComponent).join("/")}
function bytesToBase64(bytes){let binary="";const chunk=0x8000;for(let i=0;i<bytes.length;i+=chunk)binary+=String.fromCharCode(...bytes.subarray(i,i+chunk));return btoa(binary)}
function decodeBase64Utf8(base64){const binary=atob(base64.replace(/\n/g,""));const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));return new TextDecoder().decode(bytes)}
function base64url(input){return btoa(input).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
function fromBase64url(input){const padded=input.replace(/-/g,"+").replace(/_/g,"/");return atob(padded+"=".repeat((4-padded.length%4)%4))}
async function sha256Hex(value){const hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(value)));return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function hmac(secret,value){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(value)))}
async function createToken(secret){if(!secret)throw new Error("SESSION_SECRET není nastavený.");const payload={exp:Math.floor(Date.now()/1000)+8*60*60,iat:Math.floor(Date.now()/1000)};const encodedPayload=base64url(JSON.stringify(payload));const signatureBytes=await hmac(secret,encodedPayload);const signature=base64url(String.fromCharCode(...signatureBytes));return encodedPayload+"."+signature}
async function verifyToken(token,secret){try{if(!secret)return false;const parts=token.split(".");if(parts.length!==2)return false;const payload=JSON.parse(fromBase64url(parts[0]));if(!payload.exp||payload.exp<Math.floor(Date.now()/1000))return false;const expected=await hmac(secret,parts[0]);const supplied=Uint8Array.from(fromBase64url(parts[1]),c=>c.charCodeAt(0));if(expected.length!==supplied.length)return false;let diff=0;for(let i=0;i<expected.length;i++)diff|=expected[i]^supplied[i];return diff===0}catch{return false}}