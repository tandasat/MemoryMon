@echo off
del *.sdf
del *.VC.db
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q MemoryMon\x64
rmdir /s /q MemoryMon\Debug
rmdir /s /q MemoryMon\Release
cd HyperPlatform
clean.bat
cd ..
cd MemoryMonTest
clean.bat
cd ..
