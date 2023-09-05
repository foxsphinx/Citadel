It is for scan binary compiler flags.
It will call command on linux and gather info from the out put.
The commands used can be found in readme.txt
The dependency can be found in requests.txt
It needs some configuration. i.e. the path of some tools. It needs to be configured in Config/Env.txt
In Config/Dangerous.txt, it will find the binary that uses the function you list in the file. The default one is the inscure function for C. Currently, this function only supports Linux ELF file.
Usage: 
cd Citadel
python scan.py filename

Support:
windows: exe, dll, msi, cab
Linux: so, deb, rpm, tar.gz
Mac/ios: pkg, ipa,dmg
android: apk
java: jar
other: folder, zip
