// hook.js - recon for VMProtect target (Frida 17)
var T0 = Date.now();
function log(o) { o.dt = Date.now() - T0; send(o); }
function wstr(p) { try { return p.isNull() ? null : p.readUtf16String(); } catch (e) { return "<bad>"; } }
function astr(p) { try { return p.isNull() ? null : p.readUtf8String(); } catch (e) { return "<bad>"; } }

function findExport(dll, fn) {
  try { var m = Process.getModuleByName(dll); var a = m.findExportByName(fn); if (a) return a; } catch (e) {}
  try { return Module.findGlobalExportByName(fn); } catch (e) {}
  try { return Module.getGlobalExportByName(fn); } catch (e) {}
  return null;
}
function hookExport(dll, fn, cbs, quiet) {
  var addr = findExport(dll, fn);
  if (!addr) { if(!quiet) log({t:'nohook', dll:dll, fn:fn}); return; }
  try { Interceptor.attach(addr, cbs); if(!quiet) log({t:'hook', dll:dll, fn:fn, addr:addr.toString()}); }
  catch(e) { log({t:'hookfail', dll:dll, fn:fn, err:String(e)}); }
}

// ---- termination ----
hookExport('kernel32.dll','ExitProcess',{onEnter(a){ log({t:'ExitProcess', code:a[0].toInt32(), ret:this.returnAddress.toString()}); }});
hookExport('ntdll.dll','RtlExitUserProcess',{onEnter(a){ log({t:'RtlExitUserProcess', code:a[0].toInt32(), ret:this.returnAddress.toString()}); }});
hookExport('kernel32.dll','TerminateProcess',{onEnter(a){ log({t:'TerminateProcess', h:a[0].toString(), code:a[1].toInt32(), ret:this.returnAddress.toString()}); }});
hookExport('ntdll.dll','NtTerminateProcess',{onEnter(a){ log({t:'NtTerminateProcess', h:a[0].toString(), code:a[1].toInt32(), ret:this.returnAddress.toString()}); }});

// ---- admin / token checks ----
hookExport('shell32.dll','IsUserAnAdmin',{onLeave(r){ log({t:'IsUserAnAdmin', ret:r.toInt32()}); }});
hookExport('advapi32.dll','CheckTokenMembership',{onEnter(a){ this.sid=a[1]; }, onLeave(r){ log({t:'CheckTokenMembership', sid:this.sid.toString(), ret:r.toInt32()}); }});
hookExport('advapi32.dll','GetTokenInformation',{onEnter(a){
  this.cls=a[1].toInt32(); this.buf=a[2]; this.len=a[3];
}, onLeave(r){
  var val=null;
  try { if(this.cls===20) val=this.buf.readU32(); } catch(e){}
  log({t:'GetTokenInformation', cls:this.cls, ret:r.toInt32(), val:val});
}});
hookExport('advapi32.dll','OpenProcessToken',{onEnter(a){ log({t:'OpenProcessToken', acc:a[1].toInt32()}); }});

// ---- network ----
hookExport('winhttp.dll','WinHttpOpen',{onEnter(a){ log({t:'WinHttpOpen', ua:wstr(a[0]), proxy:wstr(a[3])}); }});
hookExport('winhttp.dll','WinHttpConnect',{onEnter(a){ log({t:'WinHttpConnect', host:wstr(a[1]), port:a[2].toInt32()}); }});
hookExport('winhttp.dll','WinHttpOpenRequest',{onEnter(a){ log({t:'WinHttpOpenRequest', verb:wstr(a[1]), obj:wstr(a[2]), ver:wstr(a[3]), ref:wstr(a[4])}); }});
hookExport('winhttp.dll','WinHttpSendRequest',{onEnter(a){
  var hdrs=a[1], hlen=a[2].toInt32(), body=a[3], blen=a[4].toInt32();
  var hs=null, bs=null;
  try { if(!hdrs.isNull()&&hlen>0) hs=hdrs.readUtf16String(Math.min(hlen/2,4096)); } catch(e){}
  try { if(!body.isNull()&&blen>0) bs=body.readUtf8String(Math.min(blen,8192)); } catch(e){}
  log({t:'WinHttpSendRequest', headers:hs, bodylen:blen, body:bs});
}});
hookExport('winhttp.dll','WinHttpReceiveResponse',{onEnter(a){ log({t:'WinHttpReceiveResponse'}); }});
hookExport('winhttp.dll','WinHttpQueryDataAvailable',{onEnter(a){ this.p=a[1]; }, onLeave(r){ var n=null; try{n=this.p.readU32();}catch(e){} log({t:'WinHttpQueryDataAvailable', ret:r.toInt32(), avail:n}); }});
hookExport('winhttp.dll','WinHttpReadData',{onEnter(a){ this.buf=a[1]; this.len=a[2].toInt32(); }, onLeave(r){ var s=null; try{s=this.buf.readUtf8String(Math.min(this.len,8192));}catch(e){} log({t:'WinHttpReadData', ret:r.toInt32(), len:this.len, data:s}); }});
hookExport('winhttp.dll','WinHttpQueryHeaders',{onEnter(a){ log({t:'WinHttpQueryHeaders', name:wstr(a[1])}); }});
hookExport('winhttp.dll','WinHttpSetOption',{onEnter(a){ log({t:'WinHttpSetOption', opt:a[1].toInt32()}); }});

hookExport('ws2_32.dll','getaddrinfo',{onEnter(a){ log({t:'getaddrinfo', node:astr(a[0]), service:astr(a[1])}); }});
hookExport('ws2_32.dll','connect',{onEnter(a){ log({t:'connect', fam:a[1].toInt32(), addr:hex(a[1].readByteArray(16))}); }});
hookExport('ws2_32.dll','send',{onEnter(a){ var s=null; try{s=a[1].readUtf8String(Math.min(a[2].toInt32(),4096));}catch(e){} log({t:'send', len:a[2].toInt32(), data:s}); }});
hookExport('ws2_32.dll','recv',{onEnter(a){ this.buf=a[1]; this.len=a[2].toInt32(); }, onLeave(r){ var s=null; try{s=this.buf.readUtf8String(Math.min(this.len,4096));}catch(e){} log({t:'recv', ret:r.toInt32(), data:s}); }});
function hex(ab){ if(!ab) return null; var u=new Uint8Array(ab), s=''; for(var i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }

// ---- UI ----
hookExport('user32.dll','MessageBoxW',{onEnter(a){ log({t:'MessageBoxW', text:wstr(a[1]), caption:wstr(a[2])}); }});
hookExport('user32.dll','MessageBoxA',{onEnter(a){ log({t:'MessageBoxA', text:astr(a[1]), caption:astr(a[2])}); }});
hookExport('user32.dll','SetWindowTextW',{onEnter(a){ log({t:'SetWindowTextW', text:wstr(a[1])}); }});
hookExport('user32.dll','CreateWindowExW',{onEnter(a){ log({t:'CreateWindowExW', cls:wstr(a[1]), title:wstr(a[2])}); }});
hookExport('user32.dll','CreateWindowExA',{onEnter(a){ log({t:'CreateWindowExA', cls:astr(a[1]), title:astr(a[2])}); }});
hookExport('user32.dll','CreateDialogParamW',{onEnter(a){ log({t:'CreateDialogParamW'}); }});
hookExport('user32.dll','DialogBoxParamW',{onEnter(a){ log({t:'DialogBoxParamW'}); }});

// ---- file / registry ----
hookExport('kernel32.dll','CreateFileW',{onEnter(a){ this.n=wstr(a[0]); }, onLeave(r){ if(this.n && /licen|key|auth|vanish|trace|config|settings|login|token|spoof|driver|\.sys|\.tmp/i.test(this.n)) log({t:'CreateFileW', name:this.n, ret:r.toString()}); }});

// ---- GetProcAddress tracing (import protection) ----
var gpa = findExport('kernel32.dll','GetProcAddress');
if (gpa) Interceptor.attach(gpa, {
  onEnter(a){ try { this.name=a[1].readAnsiString(); } catch(e){ this.name=null; } },
  onLeave(r){ if(this.name) log({t:'gpa', name:this.name, ret:r.toString()}); }
});

// ---- dump ----
function dumpMain(tag) {
  try {
    var m = Process.getModuleByName('VanishTrace.exe');
    var size = 0x1339000;
    var data = m.base.readByteArray(size);
    log({t:'dump', tag:tag, base:m.base.toString(), size:size, path:'main_' + tag + '.bin'});
    send({t:'dumpdata', path:'main_' + tag + '.bin'}, data);
  } catch(e) { log({t:'dumperr', err:String(e)}); }
}
setTimeout(function(){ dumpMain('t5'); }, 5000);
setTimeout(function(){ dumpMain('t10'); }, 10000);
setTimeout(function(){ log({t:'done_dump'}); }, 10500);
