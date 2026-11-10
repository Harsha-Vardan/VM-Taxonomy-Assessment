@echo off
title Taxonomy KVM Security Assessment Simulation
cd /d "%~dp0"

:menu
cls
echo ============================================================================
echo   vsec: TAXONOMY-DRIVEN SECURITY ASSESSMENT FOR KVM VIRTUALIZATION
echo   Interactive Demonstration Suite for Professors and Evaluators
echo ============================================================================
echo.
echo   [1] Run Interactive Visual Terminal Simulation (demo_visual.py)
echo   [2] Run Fast Backend Security Audit Pipeline (vsec run --simulate --fast)
echo   [3] Open the Attack Lab simulator (simulator.html)
echo   [4] Audit Single Case with Line-by-Line Controls (vsec audit)
echo   [5] Exit
echo.
echo ============================================================================
set /p choice="Select an option [1-5]: "

if "%choice%"=="1" goto visual
if "%choice%"=="2" goto pipeline
if "%choice%"=="3" goto dashboard
if "%choice%"=="4" goto audit
if "%choice%"=="5" goto end
goto menu

:visual
cls
py demo_visual.py
pause
goto menu

:pipeline
cls
echo Running Backend Security Audit Pipeline...
echo.
py scripts\make_demo_cases.py
py -u -m vsec run --simulate --fast --env E1 --vm weak=demo_cases\weak --vm hardened=demo_cases\hardened --vm weak-fixed=demo_cases\weak-fixed
echo.
echo Report generated at: %~dp0out\report.html
start "" "%~dp0out\report.html"
pause
goto menu

:dashboard
cls
echo Opening the Attack Lab simulator...
start "" "%~dp0simulator.html"
goto menu

:audit
cls
echo Running Audit on Generated Case Fixture...
echo.
py scripts\make_demo_cases.py
py -u -m vsec audit demo_cases\weak --env E1
echo.
pause
goto menu

:end
exit
