1. open folder crypto++
2. open cryptest visual studio solution 2010 (this version is comatible with 2015)
3. build project cryptest in debug mode
4. on the path crypto++/architecture/Output/Debug you can find builded cryptlib.lib
5. copy cryptlib.lib to nppcrypt/libs
6. open nppcrypt visual studio solution in folder projects/msvc2015
7. build solution
8. dll plugin is located in build/architecture 
9. add this dll to notepad++