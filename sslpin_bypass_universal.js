Java.perform(function(){
  const ArrayList = Java.use('java.util.ArrayList');
  function ok(tag){ console.log('[+] SSL bypass:', tag); }

  // 1) SSLContext.init — injecter un TrustManager permissif si aucun n'est fourni
  try{
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom')
      .implementation = function(km, tm, sr){
        let useTm = tm;
        try {
          if (!tm || tm.length === 0){
            const X509TM = Java.registerClass({
              name: 'com.frida.FriendlyTM',
              implements: [Java.use('javax.net.ssl.X509TrustManager')],
              methods: {
                checkClientTrusted: function(chain, authType){},
                checkServerTrusted: function(chain, authType){},
                getAcceptedIssuers: function(){ return Java.array('java.security.cert.X509Certificate', []); }
              }
            });
            const TMArr = Java.use('[Ljavax.net.ssl.TrustManager;');
            const arr = TMArr.$new(1); arr[0] = X509TM.$new(); useTm = arr;
            ok('Injected permissive TrustManager');
          }
        } catch(e){}
        return this.init(km, useTm, sr);
      };
    ok('SSLContext.init patched');
  }catch(e){ console.log('[-] SSLContext.init patch failed:', e.message); }

  // 2) Patch large des implémentations X509TrustManager
  try{
    Java.enumerateLoadedClasses({
      onMatch: function(name){
        const low = name.toLowerCase();
        if (low.includes('trust') || low.includes('pin')){
          try{
            const K = Java.use(name);
            ['checkServerTrusted','checkClientTrusted'].forEach(m => {
              if (K[m]) K[m].overloads.forEach(ov => {
                ov.implementation = function(){ ok(name+'.'+m+' -> allow'); return null; };
              });
            });
          }catch(_){}
        }
      }, onComplete: function(){ ok('X509TrustManager patches attempted'); }
    });
  }catch(e){ console.log('[-] enumerateLoadedClasses failed:', e.message); }

  
  ['com.android.org.conscrypt.TrustManagerImpl','org.conscrypt.TrustManagerImpl'].forEach(cls => {
    try{
      const TMI = Java.use(cls);
      ['checkTrusted','verifyChain','checkServerTrusted'].forEach(m => {
        if (TMI[m]) TMI[m].overloads.forEach(ov => {
          ov.implementation = function(){ ok(cls+'.'+m+' -> allow');
            try { return ov.apply(this, arguments); } catch(e){ try { return ArrayList.$new(); } catch(_){ return null; } }
          };
        });
      });
      ok(cls+' patched');
    }catch(e){}
  });

  
  try{
    const CP = Java.use('okhttp3.CertificatePinner');
    if (CP.check) CP.check.overloads.forEach(ov => {
      ov.implementation = function(){ ok('okhttp3.CertificatePinner.check skip'); return; };
    });
  }catch(e){}

  
  try{
    const WVC = Java.use('android.webkit.WebViewClient');
    if (WVC.onReceivedSslError) WVC.onReceivedSslError.implementation =
      function(view, handler, error){ ok('WebView onReceivedSslError -> proceed'); handler.proceed(); };
  }catch(e){}

  console.log('[+] Universal SSL pinning bypass installed');
});