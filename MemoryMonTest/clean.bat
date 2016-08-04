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
rmdir /s /q NoImage\x64
rmdir /s /q NoImage\Debug
rmdir /s /q NoImage\Release
rmdir /s /q Unlinked\x64
rmdir /s /q Unlinked\Debug
rmdir /s /q Unlinked\Release
pause
