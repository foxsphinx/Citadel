import os
import json
import Utility.globalvar as gl
import Utility.util
import Scanner.PEScanner
import Scanner.JarScanner
import Scanner.MachoScanner
import Scanner.ELFScanner
import shutil
    
def DirScan(path):
    
    files = []
    Utility.util.listFiles(path, files)
    result = {}

    for file in files:
        mime = Utility.util.checkmime(file)
        if mime == 'PE':
            tmp = Scanner.PEScanner.PEScan(file)
            #print(tmp)
            shutil.rmtree(file, ignore_errors=True)
            if tmp is None:
                continue
            
            result.update(tmp)
            
        elif mime == 'JAR':
            result.update({file: Scanner.JarScanner.JarScan(file)})
            os.remove(file)
        elif mime == 'MSI':
            result.update(Scanner.PEScanner.MSIScan(file))
            shutil.rmtree(file, ignore_errors=True)
        elif mime == 'CAB':
            result.update(Scanner.PEScanner.CABScan(file))
            shutil.rmtree(file, ignore_errors=True)
        elif mime=='ELF':
            result.update(Scanner.ELFScanner.ELFScan(file))
            #os.remove(file)
        elif mime == 'DEB':
            result.update(Scanner.ELFScanner.DebScan(file))
            shutil.rmtree(file, ignore_errors=True)    
        elif mime == 'RPM':
            result.update(Scanner.ELFScanner.RpmScan(file))
            shutil.rmtree(file, ignore_errors=True)
        elif mime=='DMG':
            result.update(Scanner.MachoScanner.DMGScan(file))
            shutil.rmtree(file, ignore_errors=True)
        elif mime=='PKG':
            result.update(Scanner.MachoScanner.PKGScan(file))
            shutil.rmtree(file, ignore_errors=True)
        elif mime=='MACHO':
            result.update(Scanner.MachoScanner.MachoScan(file))
            #shutil.rmtree(file, ignore_errors=True)
        elif mime=='ZIP':
            result.update(ZipScan(file))
            shutil.rmtree(file, ignore_errors=True)
        elif mime=='TARGZ':
            result.update(TargzScan(file))
            shutil.rmtree(file, ignore_errors=True)            
    return result

def ZipScan(path):
    path1, filename = Utility.util.normalizePath(path)
    os.system('mv %s %s.bak' % (path1, path1))
    os.system('mkdir %s' % path1)
    os.system('mv %s.bak %s/%s' % (path1, path1, filename))
    os.system('unzip -d %s %s/%s' % (path1, path1, filename))
    os.system('rm %s/%s' % (path1, filename))
    os.system('chmod 755 -R %s' % path1)
    return DirScan(path)

def TargzScan(path):
    path1, filename = Utility.util.normalizePath(path)
    os.system('mv %s %s.bak' % (path1, path1))
    os.system('mkdir %s' % path1)
    os.system('mv %s.bak %s/%s' % (path1, path1, filename))
    os.system('tar -zxvf %s/%s -C %s' % (path1, filename, path1))
    os.system('rm %s/%s' % (path1, filename))
    os.system('chmod 755 -R %s' % path1)
    return DirScan(path)

def IsoScan(path):
    path1, filename = Utility.util.normalizePath(path)
    os.system('mv %s %s.bak' % (path1, path1))
    os.system('mkdir %s1' % path1)
    os.system('sudo mount %s.bak %s1' %(path1, path1))
    os.system('cp -r %s1 %s' % (path1, path1))
    os.system('chmod -R 755 %s' % path1)
    os.system('sudo umount %s1' % path1)
    os.system('rm %s1' % path1)
    return DirScan(path)
    