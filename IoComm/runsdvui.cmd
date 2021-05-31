cd /d "G:\驱动开发代码\IoComm\IoComm" &msbuild "IoComm.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform=x64
exit %errorlevel% 