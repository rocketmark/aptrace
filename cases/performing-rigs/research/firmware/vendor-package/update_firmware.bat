@ECHO OFF
ECHO *************************************
ECHO *************************************
ECHO ** NOXON Firmware Uploader **
ECHO *************************************
ECHO *************************************

ECHO[
ECHO[

ECHO Connect the device you wish to update to a free USB port in your computer
ECHO WARNING: Be careful not to have connected any other NOXON product to the computer
ECHO:
ECHO 1.- Remote controller EU band (868 Mhz)
ECHO 2.- Remote controller North and South America band (915 MHz)
ECHO 3.- AUTOPILOT EU band (868 MHz)
ECHO 4.- AUTOPILOT North and South America band (915 MHz)
ECHO:
SET /P salida=Enter the number of the firmware you wish to upload:

IF %salida%==1 set FILENAME="firmware_mando868.bin"
IF %salida%==2 set FILENAME="firmware_mando915.bin"
IF %salida%==3 set FILENAME="firmware_autopilot868.bin"
IF %salida%==4 set FILENAME="firmware_autopilot915.bin"

FOR /F "tokens=1-3 delims=()" %%G IN ('wmic path Win32_SerialPort ^| findstr VID_239A') DO set comport=%%H
IF [%comport%]==[] (
ECHO Device not found.
SET /P salida=[Press any key to exit...]
) ELSE (
@echo off
rem: Note %~dp0 get path of this batch file
rem: Need to change drive if My Documents is on a drive other than C:
set driverLetter=%~dp0
set driverLetter=%driverLetter:~0,2%
%driverLetter%
cd %~dp0
@mode %comport%:1200
)
@timeout /T 5
FOR /F "tokens=1-3 delims=()" %%G IN ('wmic path Win32_SerialPort ^| findstr VID_239A') DO set com=%%H
IF [%comport%]==[] (
ECHO Device not found.
SET /P salida=[Press any key to exit...]
) ELSE (
bossac -i -d --port=%com% -U -i --offset=0x4000 -w -v %FILENAME% -R
ECHO Upgrade completed
SET /P salida=Press intro to exit...
)