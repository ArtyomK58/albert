const form=document.querySelector('form');
const fields=document.querySelector('fieldset');
const notice=document.querySelector('#notice');
const submit=document.querySelector('.primary');
const password=document.querySelector('#password');
let token='';
let generation=0;
function say(text,error=false){notice.textContent=text;notice.classList.toggle('error',error)}
async function send(path,payload,capability=token){
 const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${capability}`},body:JSON.stringify(payload),cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
 let body={};try{body=await response.json()}catch{}
 if(!response.ok||!body.ok)throw new Error(body.code||'network');
 return body;
}
document.querySelector('#reveal').addEventListener('click',event=>{
 const visible=password.type==='password';password.type=visible?'text':'password';
 event.currentTarget.textContent=visible?'Скрыть':'Показать';event.currentTarget.setAttribute('aria-pressed',String(visible));
});
form.addEventListener('submit',async event=>{
 event.preventDefault();if(!form.reportValidity())return;
 const current=generation;
 fields.disabled=true;submit.textContent='Сохраняем…';say('Сохраняем реквизиты.');
 try{
  await send('/vpn/enroll',{username:document.querySelector('#username').value.trim(),password:password.value});
  if(current!==generation)return;
  password.value='';token='';form.hidden=true;notice.hidden=true;document.querySelector('.intro').hidden=true;document.querySelector('.detail').hidden=true;document.querySelector('#success').hidden=false;
  document.querySelector('.card').classList.add('complete');document.querySelector('h1').textContent='Реквизиты сохранены';document.querySelector('.footer').hidden=true;
 }catch(error){
  if(current!==generation)return;
  const expired=error.message==='expired_link';
  say(expired?'Ссылка истекла. Напиши /vpn_setup в Frog Assistant, чтобы получить новую.':'Не удалось сохранить. Проверь соединение и попробуй ещё раз.',true);
  fields.disabled=expired;submit.textContent='Сохранить реквизиты';
 }
});
async function openLink(){
 const current=++generation;
 token=location.hash.slice(1);history.replaceState(null,'',location.pathname);
 password.value='';document.querySelector('#username').value='';password.type='password';
 document.querySelector('#reveal').textContent='Показать';document.querySelector('#reveal').setAttribute('aria-pressed','false');
 form.hidden=false;notice.hidden=false;document.querySelector('.intro').hidden=false;document.querySelector('.detail').hidden=false;document.querySelector('#success').hidden=true;
 document.querySelector('.card').classList.remove('complete');document.querySelector('h1').textContent='Вход в VPN';document.querySelector('.footer').hidden=false;
 fields.disabled=true;submit.textContent='Сохранить реквизиты';say('Проверяем ссылку…');
 try{
  if(!token)throw new Error('expired_link');
  await send('/vpn/check',{});if(current!==generation)return;
  fields.disabled=false;say('Ссылка действительна.');
 }catch(error){if(current===generation)say(error.message==='expired_link'?'Ссылка недействительна или истекла. Получи новую командой /vpn_setup в Frog Assistant.':'Страница временно недоступна. Открой эту же ссылку ещё раз.',true)}
}
addEventListener('hashchange',openLink);
addEventListener('pageshow',event=>{if(event.persisted)openLink()});
openLink();
