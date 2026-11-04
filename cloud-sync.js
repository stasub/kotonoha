/* ことのは帖・Firebase暗号化同期 / 検証用β版（セキュリティ監査未実施）
 * - 本文・タイトル・メモ・ルビをAES-GCMで端末側暗号化（Firestoreには暗号文のみ）
 * - Firestore revision と transaction による同時更新検知
 * - 競合時はローカルの編集を別作品として退避し、黙って上書きしない
 * - 編集画面がフォーカス中の別端末データ取込は延期
 * - オフライン時は端末内IndexedDBに保存し、オンラインに戻ったら再試行
 * ※ IndexedDBは平文。ログイン認証はE2EEとは別の仕組み。秘密鍵をバックアップしないのでパスフレーズ紛失＝復号不可。
 */
import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js';
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js';
import { getFirestore, doc, collection, getDocFromServer, getDocsFromServer, runTransaction, serverTimestamp } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js';

const firebaseConfig = {
  apiKey: 'AIzaSyCo0R79jF3PzEUPEMlhY3W95EDWb4TJb-4',
  authDomain: 'kotonoha-d74b6.firebaseapp.com',
  projectId: 'kotonoha-d74b6',
  storageBucket: 'kotonoha-d74b6.firebasestorage.app',
  messagingSenderId: '879819257900',
  appId: '1:879819257900:web:393c679a880f100f54b989'
};
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const B = window.KotonohaBridge;
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
const NOTE = '__global_note__';
let user = null;
let key = null;
let inProgress = false;
let rerun = false;
let syncTimer = 0;
let activePoll = 0;
let skippedForFocus = false;
let warningsDuringSync = false;
const saveTimers = new Map();
const b64 = raw => {
  const a = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
  let s = '';
  for (let i=0;i<a.length;i+=8192) s+=String.fromCharCode(...a.subarray(i,i+8192));
  return btoa(s);
};
const unb64 = text => Uint8Array.from(atob(text), c=>c.charCodeAt(0));
const random = len => crypto.getRandomValues(new Uint8Array(len));
const wait = ms => new Promise(resolve=>setTimeout(resolve,ms));
const isActive = () => !!(user && key && B?.ready());
const status = (s,error=false)=>{
  if(error && inProgress)warningsDuringSync=true;
  const el=$('cloudStatus');if(el){el.textContent=s;el.style.color=error?'#b24335':'#5c7865'}
  const box=$('cloudDialogMessage');if(box)box.textContent=error?s:'';
};
const report = e => {
  console.error('ことのは帖同期',e);
  const message = e?.message || String(e);
  if (/permission-denied/i.test(e?.code||'')) status('同期不可：Firestoreルールを確認',true);
  else if (/unavailable|offline|network/i.test(e?.code||'')) status('オフライン：端末保存中',true);
  else status('同期できません（端末には保存済み）',true);
  $('cloudDialogMessage').textContent='同期処理でエラーが発生したよ。コンソールも確認してね。'+message.slice(0,120);
};
const payload = (id) => id===NOTE ? ({value:B.note()}) : B.get(id);
const hash = async p => b64(await crypto.subtle.digest('SHA-256',enc.encode(JSON.stringify(p))));
const keyName = id => `${user.uid}:base:${id}`;
const reference = id => doc(db,'users',user.uid,'works',id);
const metaRef = uid => doc(db,'users',uid,'sync','meta');
const deriveKey = async(passphrase,salt,iterations=450000)=>{
  const material=await crypto.subtle.importKey('raw',enc.encode(passphrase),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
};
const encrypt = async object => {
  const iv=random(12);
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(object)));
  const ciphertext=b64(data);
  if(ciphertext.length>700000)throw new Error('作品がクラウドの1文書上限に近いため同期を停止。章分割を検討してね');
  return {format:1,iv:b64(iv),ciphertext};
};
const decrypt = async value => {
  if(value.format!==1||typeof value.iv!=='string'||typeof value.ciphertext!=='string')throw new Error('暗号データの形式が違うよ');
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(value.iv)},key,unb64(value.ciphertext))));
};
async function ensureKey(passphrase,uid){
  const d=await getDocFromServer(metaRef(uid));
  if(!d.exists()){
    const salt=random(16),k=await deriveKey(passphrase,salt);
    const iv=random(12),v=b64(await crypto.subtle.encrypt({name:'AES-GCM',iv},k,enc.encode('kotonoha-v1-correct-passphrase')));
    const newMeta={format:1,salt:b64(salt),iterations:450000,iv:b64(iv),verifier:v};
    const chosen=await runTransaction(db,async tx=>{
      const snap=await tx.get(metaRef(uid));
      if(snap.exists())return snap.data();
      tx.set(metaRef(uid),newMeta);return newMeta;
    });
    const verified=await deriveKey(passphrase,unb64(chosen.salt),chosen.iterations);
    const text=dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(chosen.iv)},verified,unb64(chosen.verifier)));
    if(text!=='kotonoha-v1-correct-passphrase')throw new Error('パスフレーズが一致しない');
    return verified;
  }
  const m=d.data();
  const k=await deriveKey(passphrase,unb64(m.salt),m.iterations);
  try{
    const text=dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(m.iv)},k,unb64(m.verifier)));
    if(text!=='kotonoha-v1-correct-passphrase')throw new Error();
  }catch{throw new Error('暗号化パスフレーズが違うよ。Firebaseログイン用とは別のものを入力してね。')}
  return k;
}
async function storedBase(id){return B.readMeta(keyName(id))}
async function writeBase(id,revision,digest,extra={}){await B.writeMeta(keyName(id),{revision,digest,...extra})}
const localList = () => {
  const list = new Map(B.list().map(w=>[w.id,w]));
  list.set(NOTE,{value:B.note()});
  return list;
};
async function importRemote(id,p,revision,expectedLocalDigest){
  if(B.editableFocused()){skippedForFocus=true;status('別端末の更新待ち：編集後に再確認');return false}
  const now=payload(id);
  if(now && await hash(now)!==expectedLocalDigest){rerun=true;return false}
  if(id===NOTE){await B.setNote(p.value||'')}
  else{if(!p || typeof p!=='object' || !p.id || p.id!==id || typeof p.text!=='string')throw new Error('受信作品の形式が不正');await B.importWork(p)}
  await writeBase(id,revision,await hash(payload(id)));
  return true;
}
async function reconcile(id,cloudSnap){
  if(!isActive())return;
  const base=await storedBase(id);
  const local=payload(id);
  const localDigest=local?await hash(local):null;
  const ref=reference(id);
  const remote=cloudSnap?.exists()?cloudSnap.data():null;
  if(remote?.deleted){
    if(local && (!base || base.revision!==remote.revision)){
      status('別端末で削除済み。こちらの原稿は端末に保護中',true);
    }
    await writeBase(id,remote.revision||0,localDigest,{deleted:true});
    return; // 安全優先：原稿の自動削除・復活はしない
  }
  if(!remote){
    if(!local)return;
    if(base){status('同期先のデータが消えています。上書きを停止',true);return}
    const encrypted=await encrypt(local);
    const written=await runTransaction(db,async tx=>{
      const snap=await tx.get(ref);
      if(snap.exists())return false;
      tx.set(ref,{...encrypted,revision:1,updatedAt:serverTimestamp(),deleted:false});return true;
    });
    if(written){await writeBase(id,1,localDigest);return}
    rerun=true;return;
  }
  if(!Number.isInteger(remote.revision)||remote.revision<1)throw new Error('同期データの版情報が不正');
  if(base && remote.revision<base.revision){status('同期履歴が食い違うため上書きを停止',true);return}
  if(!local){
    const received=await decrypt(remote);
    await importRemote(id,received,remote.revision,null);return;
  }
  if(base && remote.revision===base.revision && localDigest===base.digest)return;
  if(!base || remote.revision!==base.revision){
    const received=await decrypt(remote);
    const remoteDigest=await hash(received);
    if(remoteDigest===localDigest){await writeBase(id,remote.revision,localDigest);return}
    if(B.editableFocused()){skippedForFocus=true;status('別端末の更新待ち：編集後に再確認');return}
    if(base && localDigest===base.digest){
      await importRemote(id,received,remote.revision,localDigest);return;
    }
    // 両方が変更された・初同期で内容が異なる：ローカルを別IDで救出してからクラウドを取込む。
    if(id===NOTE){
      if(await hash(payload(id))!==localDigest){rerun=true;return}
      await B.conflictCopy({id:'local-global-note',title:'共通メモの競合退避',text:'',rubies:[],note:B.note(),updated:Date.now()});
      await importRemote(id,received,remote.revision,localDigest);
      status('共通メモ競合：端末側のメモを作品メモとして保護',true);
      rerun=true;return;
    }
    if(await hash(payload(id))!==localDigest){rerun=true;return}
    await B.conflictCopy(local);
    await importRemote(id,received,remote.revision,localDigest);
    status('競合を検出：作品コピーを保護したよ',true);
    rerun=true;return;
  }
  // 同じrevisionに対するローカル更新 → revisionの一致をTransactionで確認してから書込む。
  if(await hash(payload(id))!==localDigest){rerun=true;return}
  const encrypted=await encrypt(local);
  const committed=await runTransaction(db,async tx=>{
    const snap=await tx.get(ref);
    if(!snap.exists()||snap.data().revision!==base.revision || snap.data().deleted)return false;
    tx.set(ref,{...encrypted,revision:base.revision+1,updatedAt:serverTimestamp(),deleted:false});return true;
  });
  if(committed){await writeBase(id,base.revision+1,localDigest);return}
  rerun=true;
}
async function syncAll(){
  if(!isActive()||!navigator.onLine)return;
  if(inProgress){rerun=true;return}
  inProgress=true;skippedForFocus=false;warningsDuringSync=false;status('☁ 同期中…');
  try{
    const snap=await getDocsFromServer(collection(db,'users',user.uid,'works'));
    const remote=new Map(snap.docs.map(d=>[d.id,d]));
    const local=localList();
    for(const id of new Set([...remote.keys(),...local.keys()])){
      if(!isActive())break;
      await reconcile(id,remote.get(id));
    }
    if(!skippedForFocus && !warningsDuringSync){status('☁ 暗号化同期済み');}
  }catch(e){report(e)}finally{
    inProgress=false;
    if(rerun && isActive()){rerun=false;setTimeout(syncAll,1300)}
  }
}
function requestSync(id){
  if(!isActive())return;
  clearTimeout(saveTimers.get(id));
  saveTimers.set(id,setTimeout(()=>{saveTimers.delete(id);syncAll()},1300));
}
async function beforeDelete(id){
  if(!isActive())return true;
  if(!navigator.onLine){status('オフライン中はクラウド作品を削除できない',true);return false}
  const base=await storedBase(id);
  const ref=reference(id);
  try{
    const allowed=await runTransaction(db,async tx=>{
      const snap=await tx.get(ref);
      if(!snap.exists())return !base;
      if(!base||snap.data().revision!==base.revision||snap.data().deleted)return false;
      tx.set(ref,{format:1,revision:base.revision+1,deleted:true,updatedAt:serverTimestamp()});return true;
    });
    if(!allowed){status('削除停止：他端末の変更や未同期データを確認してね',true);return false}
    return true;
  }catch(e){report(e);return false}
}
window.KotonohaCloud={active:isActive,beforeDelete,requestSync};

$('cloudOpen').addEventListener('click',()=>{$('cloudDialog').showModal()});
$('cloudClose').addEventListener('click',()=>{$('cloudDialog').close()});
$('cloudLogout').addEventListener('click',async()=>{
  key=null;user=null;
  try{await signOut(auth)}catch(e){report(e)}
  clearInterval(activePoll);status('クラウドからログアウト');$('cloudDialog').close();
});
$('cloudConnect').addEventListener('click',async()=>{
  const button=$('cloudConnect');
  const email=$('cloudEmail').value.trim();
  const pw=$('cloudPassword').value;
  const phrase=$('cloudPassphrase').value;
  if(phrase.length<12){status('暗号化パスフレーズは12文字以上にしてね',true);return}
  if(!crypto?.subtle){status('HTTPS接続が必要だよ',true);return}
  button.disabled=true;
  try{
    status('ログイン・暗号化鍵を確認中…');
    const credential=await signInWithEmailAndPassword(auth,email,pw);
    const uid=credential.user.uid;
    const owner=await B.readMeta('owner');
    if(owner && owner!==uid)throw new Error('この端末は別のFirebaseユーザーにひもづいてるよ。データの混在を防ぐため同期を停止したよ');
    const newKey=await ensureKey(phrase,uid);
    user=credential.user;
    key=newKey;
    await B.writeMeta('owner',uid);
    $('cloudPassword').value='';$('cloudPassphrase').value='';
    $('cloudDialog').close();
    await syncAll();
    clearInterval(activePoll);
    activePoll=setInterval(()=>{if(document.visibilityState==='visible'&&navigator.onLine)syncAll()},120000);
    B.notify('暗号化同期のテストを開始したよ');
  }catch(e){
    key=null;user=null;report(e);
    // 誤ったキー・ユーザーはログイン状態にも残さない。
    try{await signOut(auth)}catch{}
  }finally{button.disabled=false}
});
window.addEventListener('kotonoha:worksaved',e=>requestSync(e.detail?.id));
window.addEventListener('kotonoha:notesaved',()=>requestSync(NOTE));
window.addEventListener('online',()=>syncAll());
window.addEventListener('focus',()=>{if(isActive())syncAll()});
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')syncAll()});
document.addEventListener('focusout',()=>{
  if(skippedForFocus){setTimeout(()=>{if(!B.editableFocused())syncAll()},500)}
});
onAuthStateChanged(auth,u=>{
  if(u&&!key)status('ログイン済み・原稿の鍵を入力してね');
  else if(!u&&!key)status('クラウド未接続');
});
status('クラウド未接続');
