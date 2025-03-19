@echo off
:: Batch script to compile C files using cl.exe

:: Set the path to the Visual Studio environment variables
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

:: Specify the source file and output executable
set SOURCE_FILE=PE-PARSER.c
set OUTPUT_FILE=main.exe

:: Compile the source file as C code and link against required libraries
cl /TC /EHsc %SOURCE_FILE% /Fe:%OUTPUT_FILE% /link kernel32.lib

:: Check if the compilation was successful
if %ERRORLEVEL% equ 0 (
    echo Compilation successful. Executable: %OUTPUT_FILE%
) else (
    echo Compilation failed.
)
pause