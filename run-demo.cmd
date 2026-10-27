@echo off
rem Runs the live presentation demo. Double-click this file, or type run-demo in a terminal.
cd /d "%~dp0pq-handshake"
"%USERPROFILE%\.venvs\pq-handshake\Scripts\python.exe" demo.py %*
if "%~1"=="" pause
