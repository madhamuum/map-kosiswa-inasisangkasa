const {createClient}=require('@supabase/supabase-js');
const crypto=require('crypto');
const {PDFDocument}=require('pdf-lib');
const fs=require('fs');
const path=require('path');
const names=require('../public/members.json');
const lookup=Object.fromEntries(names.map(m=>[m.number,m]));
const db=()=>createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
function hashCode(code){return crypto.createHash('sha256').update(process.env.SIGNING_PEPPER+':'+code.trim().toUpperCase()).digest('hex')}
function match(a,b){let x=Buffer.from(a||'','utf8'),y=Buffer.from(b||'','utf8');return x.length===y.length&&crypto.timingSafeEqual(x,y)}
function admin(req){return !!process.env.ADMIN_KEY&&match(req.headers['x-admin-key'],process.env.ADMIN_KEY)}
function fail(res,status,error){return res.status(status).json({error})}
function location(num){if(num<=5)return [0,[384,469,554,639,723][num-1]];if(num<=14)return [1,[99,184,268,345,422,507,592,676,745][num-6]];if(num<=22)return [2,[136,221,306,391,475,560,645,721][num-15]];return [3,[99,184,268,353,438,523,607][num-23]]}
module.exports=async(req,res)=>{
 try{
  if(!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_ROLE_KEY||!process.env.SIGNING_PEPPER) return fail(res,503,'Pelayan belum dikonfigurasi.');
  const act=(req.query.action||'').toString();
  if(act==='sign' && req.method==='POST'){
   const body=typeof req.body==='string'?JSON.parse(req.body):req.body||{};
   const number=Number(body.number), code=String(body.code||''), sig=String(body.signature||'');
   if(!Number.isInteger(number)||number<1||number>29||code.length>80||!body.consent||!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(sig)||sig.length>170000) return fail(res,400,'Maklumat atau tandatangan tidak sah.');
   const client=db();const {data:record,error}=await client.from('angkasa_signatures').select('member_number,code_hash,signed_at').eq('member_number',number).single();
   if(error||!record||!match(hashCode(code),record.code_hash))return fail(res,403,'Nama atau kod pengesahan tidak sepadan.');
   if(record.signed_at)return fail(res,409,'Tandatangan telah direkodkan. Hubungi pentadbir jika perlu pembetulan.');
   const {data:written,error:writeError}=await client.from('angkasa_signatures').update({signature_data:sig,consent_at:new Date().toISOString(),signed_at:new Date().toISOString(),signature_version:1}).eq('member_number',number).is('signed_at',null).select('member_number');
   if(writeError)return fail(res,500,'Gagal menyimpan tandatangan.');
   if(!written?.length)return fail(res,409,'Tandatangan sudah direkodkan.');
   return res.json({ok:true,member:lookup[number].name});
  }
  if(act==='status' && req.method==='GET'){
   if(!admin(req))return fail(res,401,'Kata laluan admin tidak sah.');
   const {data,error}=await db().from('angkasa_signatures').select('member_number,member_name,signed_at').order('member_number');
   if(error)throw error;return res.json({members:data||[]});
  }
  if(act==='export' && req.method==='GET'){
   if(!admin(req))return fail(res,401,'Kata laluan admin tidak sah.');
   const {data,error}=await db().from('angkasa_signatures').select('member_number,signature_data,signed_at').order('member_number');
   if(error)throw error;
   const doc=await PDFDocument.load(fs.readFileSync(path.join(process.cwd(),'source.pdf')));
   for(const row of data||[]){if(!row.signed_at||!row.signature_data||row.member_number>29)continue;
    const [pageIndex,yTop]=location(row.member_number);const page=doc.getPage(pageIndex);const png=await doc.embedPng(Buffer.from(row.signature_data.split(',')[1],'base64'));
    const width=104,height=37;page.drawImage(png,{x:476,y:page.getHeight()-yTop-height/2,width,height,opacity:1});
   }
   // Mark as electronically collected; does not certify identity or legal validity.
   const buf=await doc.save();res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition','attachment; filename="Lampiran_Kehadiran_Bertandatangan.pdf"');return res.send(Buffer.from(buf));
  }
  return fail(res,404,'Laluan tidak dijumpai.');
 }catch(e){console.error(e);return fail(res,500,'Ralat pelayan. Sila cuba lagi.');}
};
