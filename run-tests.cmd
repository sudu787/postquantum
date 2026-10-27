@echo off
rem Runs all 35 tests. Double-click this file, or type run-tests in a terminal.
cd /d "%~dp0pq-handshake"
"%USERPROFILE%\.venvs\pq-handshake\Scripts\python.exe" -m pytest tests -v -p no:cacheprovider
if "%~1"=="" pause
