@ECHO OFF

REM Minimal make.bat for Sphinx documentation

set SPHINXBUILD=sphinx-build
set SOURCEDIR=source
set BUILDDIR=_build

if "%1"=="" goto help

if "%1"=="clean" goto clean
if "%1"=="html" goto html

:help
%SPHINXBUILD% -M help %SOURCEDIR% %BUILDDIR%
goto end

:clean
rmdir /S /Q %BUILDDIR% 2>NUL
rmdir /S /Q %SOURCEDIR%\autoapi 2>NUL
goto end

:html
%SPHINXBUILD% -b html %SOURCEDIR% %BUILDDIR%\html
goto end

:end

