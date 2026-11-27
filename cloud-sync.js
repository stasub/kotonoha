/* ことのは帖・Firebase暗号化同期 / 検証用β版（セキュリティ監査未実施）
 * - 本文・タイトル・メモ・ルビをAES-GCMで端末側暗号化（Firestoreには暗号文のみ）
 * - Firestore revision と transaction による同時更新検知
 * - 競合時はローカルの編集を別作品として退避し、黙って上書きしない
 * - 編集画面がフォーカス中の別端末データ取込は延期
 * - オフライン時は端末内IndexedDBに保存し、オンラインに戻ったら再試行
 * ※ IndexedDBは平文。ログイン認証はE2EEとは別の仕組み。秘密鍵をバックアップしないのでパスフレーズ紛失＝復号不可。
 */
import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js';
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut, setPersistence, browserLocalPersistence } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js';
import { getFirestore, doc, collection, getDocFromServer, getDocsFromServer, onSnapshot, runTransaction, serverTimestamp } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js';

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
const NOTE = 'global-note-v1';
let user = null;
let key = null;
let connecting = false;
let connectStep = '';
let lastErrorAt = 0;
let connectionWatchdog = 0;
const CONNECT_VERSION = '同期改善 v1.2q';
let inProgress = false;
let rerun = false;
let syncTimer = 0;
let activePoll = 0;
let unsubscribe = null, expiryTimer = 0, expiresAt = 0;
let stopping = false, restoring = false, restorePending = false;
let lockEpoch=0;
let lastSync = '', retryTimer = 0;
const KEY_SLOT = 'trusted-key-v12q';
const TTL = 24*60*60*1000;
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
const isActive = () => !!(user && key && B?.ready() && !stopping && auth.currentUser?.uid===user.uid && (!expiresAt || Date.now()<expiresAt));
const canReceive = () => B.syncReady() && !B.editableFocused();
const status = (s,error=false)=>{
  if(error && inProgress)warningsDuringSync=true;
  const el=$('cloudStatus');if(el){el.textContent=s;el.style.color=error?'#b24335':'#5c7865'}
  const box=$('cloudDialogMessage');if(box)box.textContent=error?s:'';
};
// ログイン中は背後のヘッダーだけでなく、ダイアログ内に処理状況を表示する。
// UI上の経過表示であり、通信や暗号化の成功を意味しない。
const showConnectStep = (label) => {
  connectStep=label;
  status(label);
  const box=$('cloudDialogMessage');
  if(box){box.style.color='#5c7865';box.textContent=label;}
};
const report = e => {
  console.error('ことのは帖同期',e);
  const message = String(e?.message || e || '不明なエラー').slice(0,200);
  const code = e?.code ? ` [${e.code}]` : '';
  if (/permission-denied/i.test(e?.code||'')) status('同期不可：Firestoreルールを確認',true);
  else if (/unavailable|offline|network/i.test(e?.code||'')) status('オフライン：端末保存中',true);
  else status('同期できません（端末には保存済み）',true);
  const box=$('cloudDialogMessage');
  if(box){box.style.color='#b24335';box.textContent=`${connectStep || '同期中'}でエラー${code}: ${message}`;}
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
  if(!isActive()||!canReceive()){skippedForFocus=true;status('別端末の更新待ち：編集後に再確認');return false}
  const now=payload(id);
  if(now && await hash(now)!==expectedLocalDigest){rerun=true;return false}
  if(!isActive() || !canReceive()){skippedForFocus=true;return false}
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
    if(!isActive())return;
    const written=await runTransaction(db,async tx=>{
      const snap=await tx.get(ref);
      if(!isActive()||snap.exists())return false;
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
    if(!isActive()||!canReceive()){skippedForFocus=true;status('別端末の更新待ち：編集後に再確認');return}
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
  if(!isActive())return;
  const committed=await runTransaction(db,async tx=>{
    const snap=await tx.get(ref);
    if(!isActive()||!snap.exists()||snap.data().revision!==base.revision || snap.data().deleted)return false;
    tx.set(ref,{...encrypted,revision:base.revision+1,updatedAt:serverTimestamp(),deleted:false});return true;
  });
  if(committed){await writeBase(id,base.revision+1,localDigest);return}
  rerun=true;
}
async function syncAll(){
  if(expiresAt && Date.now()>=expiresAt){void lockSync(false);return;}
  if(!isActive())return;
  if(!navigator.onLine){status('オフライン：端末保存中',true);return;}
  if(inProgress){rerun=true;return}
  if(!B.syncReady()){status('端末保存・文字変換の完了待ち');scheduleRetry();return;}
  inProgress=true;skippedForFocus=false;warningsDuringSync=false;status('☁ 同期中…');
  try{
    const snap=await getDocsFromServer(collection(db,'users',user.uid,'works'));
    const remote=new Map(snap.docs.map(d=>[d.id,d]));
    const local=localList();
    for(const id of new Set([...remote.keys(),...local.keys()])){
      if(!isActive())break;
      if(!B.syncReady()){skippedForFocus=true;status('端末保存・文字変換の完了待ち');break;}
      await reconcile(id,remote.get(id));
    }
    if(isActive() && !skippedForFocus && !warningsDuringSync && !rerun){lastSync=new Date().toLocaleTimeString('ja-JP');status('☁ 同期済み '+lastSync);}
    if(skippedForFocus && isActive() && !B.editableFocused())scheduleRetry();
  }catch(e){report(e)}finally{
    inProgress=false;
    if(rerun && isActive()){rerun=false;scheduleRetry();}
  }
}
function scheduleRetry(){
  clearTimeout(retryTimer);retryTimer=setTimeout(()=>{if(document.visibilityState==='visible')void syncAll()},5000);
}
function stopWatch(){
  clearInterval(activePoll);clearTimeout(syncTimer);clearTimeout(retryTimer);clearTimeout(expiryTimer);
  if(unsubscribe){unsubscribe();unsubscribe=null;}
  for(const timer of saveTimers.values())clearTimeout(timer);saveTimers.clear();rerun=false;
}
function startWatch(){
  stopWatch();
  if(expiresAt)expiryTimer=setTimeout(()=>void lockSync(false),Math.max(0,expiresAt-Date.now()));
  // Listener is a notification only: all writes and imports still use the original server-read / revision logic.
  unsubscribe=onSnapshot(collection(db,'users',user.uid,'works'),{includeMetadataChanges:true},snap=>{
    if(snap.metadata.fromCache || snap.metadata.hasPendingWrites || !isActive())return;
    clearTimeout(syncTimer);syncTimer=setTimeout(()=>{if(document.visibilityState==='visible')void syncAll()},600);
  },e=>{console.warn('同期の変更通知',e);});
  activePoll=setInterval(()=>{if(document.visibilityState==='visible')void syncAll()},120000);
}
async function waitForBridge(){
  for(let i=0;i<100&&!B.ready();i++)await wait(100);
  if(!B.ready())throw new Error('端末保存の準備ができていないよ');
}
async function clearRemembered(){await B.deleteMeta(KEY_SLOT);}
async function lockSync(logout=false){
  if(stopping)return;
  stopping=true;lockEpoch++;restorePending=false;stopWatch();
  $('cloudLock').disabled=true;$('cloudLogout').disabled=true;$('cloudConnect').disabled=true;
  try{
    // An already-started transaction is allowed to finish; no new sync is started.
    await waitForBridge();
    await clearRemembered();
    status('暗号化鍵ロック中：進行中の同期終了待ち');
    while(inProgress)await wait(100);
    key=null;user=null;expiresAt=0;
    if(logout){await signOut(auth);$('cloudDialog').close();}
    status(logout?'クラウドからログアウト':'暗号化鍵ロック中：パスフレーズを入力');
  }catch(e){while(inProgress)await wait(100);key=null;user=null;expiresAt=0;status('保存した鍵の削除・ログアウトを確認できません',true);console.error(e);}
  finally{stopping=false;$('cloudLock').disabled=false;$('cloudLogout').disabled=false;$('cloudConnect').disabled=false;}
}
async function restoreSession(u){
  if(!u||connecting||restoring||stopping||key)return;
  restoring=true;
  const epoch=lockEpoch;
  try{
    await waitForBridge();
    if(auth.currentUser?.uid!==u.uid || epoch!==lockEpoch)return;
    const owner=await B.readMeta('owner');
    const saved=await B.readMeta(KEY_SLOT);
    if(epoch!==lockEpoch || auth.currentUser?.uid!==u.uid)return;
    if(saved?.uid===u.uid && owner===u.uid)$('cloudRemember').checked=true;
    if(owner!==u.uid || !saved || saved.uid!==u.uid || !Number.isFinite(saved.expiresAt) || saved.expiresAt<=Date.now() || saved.expiresAt>Date.now()+TTL || saved.key?.type!=='secret' || saved.key?.extractable!==false || saved.key?.algorithm?.name!=='AES-GCM'){
      if(saved)await clearRemembered();
      restorePending=false;status('ログイン済み・原稿の鍵を入力してね');return;
    }
    $('cloudRemember').checked=true;
    if(!navigator.onLine){restorePending=true;status('オフライン：接続後に鍵を確認');return;}
    // Never accept a remembered key against a different encryption configuration.
    const snap=await getDocFromServer(metaRef(u.uid));
    if(!snap.exists())throw new Error('暗号化設定が見つからないよ');
    const m=snap.data();
    const text=dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(m.iv)},saved.key,unb64(m.verifier)));
    if(text!=='kotonoha-v1-correct-passphrase')throw new Error('保存した鍵が一致しないよ');
    if(auth.currentUser?.uid!==u.uid || stopping || connecting || epoch!==lockEpoch || Date.now()>=saved.expiresAt)return;
    // Re-read to detect a manual lock from another tab while verification was pending.
    const latest=await B.readMeta(KEY_SLOT);
    if(!latest || latest.expiresAt!==saved.expiresAt || stopping || connecting || epoch!==lockEpoch || Date.now()>=saved.expiresAt || auth.currentUser?.uid!==u.uid)return;
    user=u;key=saved.key;expiresAt=saved.expiresAt;restorePending=false;startWatch();void syncAll();
  }catch(e){if(epoch===lockEpoch){restorePending=true;status('鍵の自動確認ができません。再同期またはパスフレーズを入力',true);console.warn(e);}}
  finally{restoring=false;}
}
function requestSync(id){
  if(!isActive())return;
  clearTimeout(saveTimers.get(id));
  saveTimers.set(id,setTimeout(()=>{saveTimers.delete(id);syncAll()},1300));
}
async function beforeDelete(id){
  if(stopping || (expiresAt && Date.now()>=expiresAt)){status('暗号化鍵のロック処理中：削除を停止',true);return false;}
  if(!isActive())return true;
  if(!navigator.onLine){status('オフライン中はクラウド作品を削除できない',true);return false}
  const base=await storedBase(id);
  const ref=reference(id);
  try{
    const allowed=await runTransaction(db,async tx=>{
      const snap=await tx.get(ref);
      if(!isActive())return false;
      if(!snap.exists())return !base;
      if(!base||snap.data().revision!==base.revision||snap.data().deleted)return false;
      tx.set(ref,{format:1,revision:base.revision+1,deleted:true,updatedAt:serverTimestamp()});return true;
    });
    if(!allowed){status('削除停止：他端末の変更や未同期データを確認してね',true);return false}
    return true;
  }catch(e){report(e);return false}
}
window.KotonohaCloud={active:isActive,beforeDelete,requestSync};

$('cloudSyncNow').addEventListener('click',async()=>{
  if(connecting||restoring||stopping)return;
  if(!isActive()){if(restorePending&&auth.currentUser){await restoreSession(auth.currentUser);if(isActive())return;} $('cloudOpen').click();return;}
  // A deliberate tap ends focus, but never force a blur during IME finalization.
  if(B.syncReady() && B.editableFocused())document.activeElement?.blur();
  await wait(500);
  if(!isActive())return;
  if(!B.syncReady()||B.editableFocused()){status('入力確定・保存後に同期します');scheduleRetry();return;}
  await syncAll();
});

$('cloudOpen').addEventListener('click',()=>{
  const u=auth.currentUser;
  if(u?.email)$('cloudEmail').value=u.email;
  $('cloudDialog').showModal();
  const box=$('cloudDialogMessage');
  if(box && !connecting){
    box.style.color='#5c7865';
    box.textContent=isActive()? (expiresAt?'鍵の保持期限：'+new Date(expiresAt).toLocaleString('ja-JP'):'暗号化同期は接続中') : u?'ログイン済み。パスワード欄は空欄のまま、パスフレーズを入力してね。':`${CONNECT_VERSION} を読み込み済み。`;
  }
});
$('cloudClose').addEventListener('click',()=>{$('cloudDialog').close()});
$('cloudLock').addEventListener('click',()=>{if(!connecting)void lockSync(false)});
$('cloudLogout').addEventListener('click',()=>{if(!connecting)void lockSync(true)});
$('cloudConnect').addEventListener('click',async()=>{
  // 二重送信を防ぎ、何が進行しているか必ず画面に表示する。
  if(connecting||restoring||stopping)return;
  const button=$('cloudConnect');
  const email=$('cloudEmail').value.trim();
  const pw=$('cloudPassword').value;
  const phrase=$('cloudPassphrase').value;
  const existing=auth.currentUser;
  const reuse=!!(existing && existing.email===email && !pw);
  if(!reuse && (!email||!pw)){
    const box=$('cloudDialogMessage');
    if(box){box.style.color='#b24335';box.textContent='メールアドレスとログイン用パスワードを入力してね';}
    return;
  }
  if(phrase.length<12){
    const box=$('cloudDialogMessage');
    if(box){box.style.color='#b24335';box.textContent='暗号化パスフレーズは12文字以上にしてね';}
    return;
  }
  if(!window.crypto?.subtle){
    const box=$('cloudDialogMessage');
    if(box){box.style.color='#b24335';box.textContent='HTTPSの安全な接続が必要だよ';}
    return;
  }
  if(!navigator.onLine){
    const box=$('cloudDialogMessage');
    if(box){box.style.color='#b24335';box.textContent='オフラインのようだよ。ネット接続を確認してね';}
    return;
  }
  connecting=true;
  button.disabled=true;
  const originalText=button.textContent;
  button.textContent='接続を確認中…';
  showConnectStep('① Firebaseへログイン中…');
  // 長時間待ちになった場合、原因を追えるようダイアログに案内する。
  // ネットワーク処理は勝手にキャンセルせず、同時リクエストも発行しない。
  connectionWatchdog=setTimeout(()=>{
    const box=$('cloudDialogMessage');
    if(connecting && box){
      box.style.color='#a04c3c';
      box.textContent=`${connectStep}（応答に時間がかかっています。電波やSafariの通信を確認してね。タブを開き直しても端末内データは消えません。「Webサイトデータを削除」はしないでね）`;
    }
  },15000);
  try{
    await waitForBridge();
    // Do not replace an active key/account while a previous sync is running.
    stopWatch();while(inProgress)await wait(100);
    key=null;user=null;expiresAt=0;restorePending=false;
    await clearRemembered();
    if(!reuse){try{await setPersistence(auth,browserLocalPersistence)}catch(e){console.warn('ログイン状態を保持できません',e);}}
    const credential=reuse?{user:existing}:await signInWithEmailAndPassword(auth,email,pw);
    const uid=credential.user.uid;
    showConnectStep('② Firebaseログイン成功。端末データと暗号化鍵を確認中…');
    const owner=await B.readMeta('owner');
    if(owner && owner!==uid)throw new Error('この端末は別のFirebaseユーザーにひもづいてるよ。データの混在を防ぐため同期を停止したよ');
    const newKey=await ensureKey(phrase,uid);
    showConnectStep('③ 暗号化鍵の確認成功。同期を準備中…');
    user=credential.user;
    key=newKey;
    await B.writeMeta('owner',uid);
    let rememberFailed=false;
    if($('cloudRemember').checked){
      const deadline=Date.now()+TTL;
      try{await B.writeMeta(KEY_SLOT,{uid,key:newKey,expiresAt:deadline});expiresAt=deadline;}
      catch(e){rememberFailed=true;console.warn('鍵の端末保存に失敗',e);}
    }
    $('cloudPassword').value='';$('cloudPassphrase').value='';
    $('cloudDialog').close();
    startWatch();await syncAll();
    B.notify(rememberFailed?'鍵を保存できなかったため、再起動時は再入力してね':'暗号化同期のテストを開始したよ');
  }catch(e){
    stopWatch();key=null;user=null;expiresAt=0;report(e);
    try{await clearRemembered()}catch{}
    // 誤ったキー・ユーザーはログイン状態にも残さない。
    try{await signOut(auth)}catch{}
  }finally{
    clearTimeout(connectionWatchdog);
    connecting=false;
    button.disabled=false;
    button.textContent=originalText;
  }
});
window.addEventListener('kotonoha:worksaved',e=>requestSync(e.detail?.id));
window.addEventListener('kotonoha:notesaved',()=>requestSync(NOTE));
function wake(){
  if(expiresAt && Date.now()>=expiresAt){void lockSync(false);return;}
  if(restorePending && auth.currentUser)void restoreSession(auth.currentUser);
  else if(isActive())void syncAll();
}
window.addEventListener('online',wake);
window.addEventListener('focus',wake);
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')wake()});
document.addEventListener('focusout',()=>{
  if(skippedForFocus){setTimeout(()=>{if(!B.editableFocused())void syncAll()},500)}
});
onAuthStateChanged(auth,u=>{
  if(connecting||stopping)return;
  if(user && user.uid!==u?.uid){void lockSync(false);return;}
  if(u&&!key)void restoreSession(u);
  else if(!u&&!key){restorePending=false;status('クラウド未接続');void waitForBridge().then(()=>{if(!auth.currentUser && !connecting)return clearRemembered();}).catch(console.warn);}
});
status('クラウド未接続');
