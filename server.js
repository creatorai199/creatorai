require("dotenv").config();
const express=require("express"), path=require("path"), Database=require("better-sqlite3");
const bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), cookieParser=require("cookie-parser");
const crypto=require("crypto");
const Razorpay=require("razorpay");
const app=express();
const db=new Database("creatorai.db");

db.exec(`CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,
 plan TEXT DEFAULT 'free',subscription_id TEXT,subscription_status TEXT DEFAULT 'inactive',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);`);

// Razorpay webhook MUST receive the raw request body for signature verification.
app.post("/api/razorpay-webhook",express.raw({type:"application/json"}),(req,res)=>{
 try{
  const signature=req.get("X-Razorpay-Signature");
  const secret=process.env.RAZORPAY_WEBHOOK_SECRET;
  if(!secret) return res.status(500).send("Webhook secret not configured");
  const expected=crypto.createHmac("sha256",secret).update(req.body).digest("hex");
  if(!signature || !crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(signature))) return res.status(400).send("Invalid signature");

  const event=JSON.parse(req.body.toString("utf8"));
  const entity=event.payload?.subscription?.entity;
  if(entity?.id){
   const status=entity.status;
   const active=["active","authenticated"].includes(status);
   const plan=active?"pro":"free";
   db.prepare("UPDATE users SET plan=?,subscription_status=? WHERE subscription_id=?").run(plan,status,entity.id);
  }
  res.sendStatus(200);
 }catch(e){
  console.error("Webhook error",e);
  res.sendStatus(400);
 }
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname,"public")));

const JWT_SECRET=process.env.JWT_SECRET||"dev-only-change-me";
const rp=(process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET)
 ? new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET}) : null;

function auth(req,res,next){
 const token=req.cookies.token;
 if(!token) return res.status(401).json({error:"Login required"});
 try{req.user=jwt.verify(token,JWT_SECRET);next()}catch(e){return res.status(401).json({error:"Session expired"})}
}
function tokenFor(user){return jwt.sign({id:user.id,email:user.email},JWT_SECRET,{expiresIn:"7d"})}

app.post("/api/signup",async(req,res)=>{
 const {email,password}=req.body||{};
 if(!email||!password||password.length<8) return res.status(400).json({error:"Enter a valid email and password of at least 8 characters."});
 try{
  const clean=email.toLowerCase().trim();
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").run(clean,hash);
  const user={id:info.lastInsertRowid,email:clean};
  res.cookie("token",tokenFor(user),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*864e5});
  res.json({ok:true,user});
 }catch(e){res.status(409).json({error:"That email is already registered."})}
});

app.post("/api/login",async(req,res)=>{
 const {email,password}=req.body||{};
 const user=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase().trim());
 if(!user||!(await bcrypt.compare(password||"",user.password_hash))) return res.status(401).json({error:"Invalid email or password."});
 res.cookie("token",tokenFor(user),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*864e5});
 res.json({ok:true});
});
app.post("/api/logout",(req,res)=>{res.clearCookie("token");res.json({ok:true})});

app.get("/api/me",auth,(req,res)=>{
 const user=db.prepare("SELECT id,email,plan,subscription_id,subscription_status,created_at FROM users WHERE id=?").get(req.user.id);
 res.json(user);
});

app.post("/api/create-subscription",auth,async(req,res)=>{
 if(!rp) return res.status(503).json({error:"Razorpay is not configured. Add your Test API Key ID and Key Secret to .env."});
 if(!process.env.RAZORPAY_PLAN_ID) return res.status(503).json({error:"Razorpay plan ID is missing."});
 try{
  const existing=db.prepare("SELECT subscription_id,subscription_status FROM users WHERE id=?").get(req.user.id);
  if(existing?.subscription_id && ["created","authenticated","active","pending"].includes(existing.subscription_status)){
   return res.json({subscriptionId:existing.subscription_id,keyId:process.env.RAZORPAY_KEY_ID,reused:true});
  }
  const sub=await rp.subscriptions.create({
   plan_id:process.env.RAZORPAY_PLAN_ID,
   total_count:1200,
   quantity:1,
   customer_notify:1,
   notes:{creatorai_user_id:String(req.user.id),email:req.user.email}
  });
  db.prepare("UPDATE users SET subscription_id=?,subscription_status=? WHERE id=?").run(sub.id,sub.status,req.user.id);
  res.json({subscriptionId:sub.id,keyId:process.env.RAZORPAY_KEY_ID});
 }catch(e){
  console.error(e);
  res.status(500).json({error:e.error?.description||e.message||"Could not create subscription."});
 }
});

app.post("/api/verify-subscription",auth,(req,res)=>{
 const {razorpay_payment_id,razorpay_subscription_id,razorpay_signature}=req.body||{};
 if(!razorpay_payment_id||!razorpay_subscription_id||!razorpay_signature) return res.status(400).json({error:"Missing Razorpay verification fields."});
 const user=db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
 if(!user || user.subscription_id!==razorpay_subscription_id) return res.status(400).json({error:"Subscription does not belong to this account."});
 const body=`${razorpay_payment_id}|${razorpay_subscription_id}`;
 const expected=crypto.createHmac("sha256",process.env.RAZORPAY_KEY_SECRET).update(body).digest("hex");
 if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(razorpay_signature))) return res.status(400).json({error:"Payment verification failed."});
 db.prepare("UPDATE users SET plan='pro',subscription_status='authenticated' WHERE id=?").run(req.user.id);
 res.json({ok:true,plan:"pro",subscription_status:"authenticated"});
});

app.post("/api/generate",auth,(req,res)=>{
 const user=db.prepare("SELECT plan FROM users WHERE id=?").get(req.user.id);
 if(user.plan!=="pro") return res.status(403).json({error:"Creator Pro is required. Upgrade for ₹199/month."});
 const {prompt,type="video"}=req.body||{};
 if(!prompt||prompt.length<5) return res.status(400).json({error:"Enter a prompt."});
 res.json({ok:true,status:"queued",type,prompt,message:"Your CreatorAI generation endpoint is ready. Connect an AI video/image/voice provider to return the finished media."});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log(`CreatorAI running on http://localhost:${process.env.PORT||3000}`));
