import lief
import os
import Utility.globalvar as gl
import Utility.util
import Scanner.PEScanner
import Scanner.JarScanner
import Scanner.ELFScanner

from lief.MachO import HEADER_FLAGS
def get_file(path):
    f=[]
    for filepath, dirnames,filenames in os.walk(path):
        for filename in filenames:
            f.append(os.path.join(filepath,filename))
    return f
def extractpkgfile(pkgfile):
    if not os.path.exists('./tmp'):        
        os.makedirs('./tmp')
    (newpath, pkgname) = Utility.util.normalizePath(pkgfile)
    os.system('mv %s %s.bak' % (newpath, newpath))
    os.system('mkdir %s' % newpath)
    os.system('mv %s.bak %s/' % (newpath, newpath))
    os.system('mv %s/%s.bak %s/%s' % (newpath, pkgname, newpath, pkgname))
    os.system('7z x %s/%s' %(newpath, pkgname))
    os.system("mv Payload~ %s/Payload" % newpath)
    os.system("rm %s/%s" % (newpath, pkgname))
    os.system("cpio -D %s/%s -idvmc < %s/Payload" % (newpath, pkgname, newpath))
    os.system("rm %s/Payload" % newpath)
    
def PKGScan(pathfile):
    #scanfilename=pathfile.split('/')[-1]
    gl.init()
    files=[]    
    extractpkgfile(pathfile)
    #path='./tmp'
    result={}        
    Utility.util.listFiles(pathfile, files)
    #numofMACHO=0
    #print("finish script")
    for i in files:
        mime=Utility.util.checkmime(i)
        if mime == 'PE':
            #numofPE=numofPE+1
            val=Scanner.PEScanner.PEScan(i)
            result.update(val)
        if mime == 'ELF':
            #numofELF=numofELF+1
            val=Scanner.ELFScanner.ELFScan(i)
            result.update(val)
        if mime == 'MACHO':
            #numofMACHO=numofMACHO+1
            #print("machoscan")
            val=MachoScan(i)
            result.update(val)               
        if mime == 'JAR':
            #numofJar=numofJar+1
            val=Scanner.JarScanner.JarScan(i)
            result.update(val)
    return result
    #finale=Utility.util.parseResult(result)
    #Utility.util.genReport(finale,scanfilename)
    #Utility.util.deleteTmp()        
    
def DMGScan(path):
    #scanfilename=path.split('/')[-1]
    gl.init()
    files=[]
    newpath, dmgname = Utility.util.normalizePath(path)
    cmd = 'sh ./Utility/unarchievedmg.sh ' + newpath
    os.system(cmd)
    #path='./tmp/' + dmgname
    result={}        
    Utility.util.listFiles(path, files)
    #numofMACHO=0
    #print("finish script")
    for i in files:       
        mime=Utility.util.checkmime(i)
        if mime == 'PE':
            #numofPE=numofPE+1
            val=Scanner.PEScanner.PEScan(i)
            result.update(val)
        if mime == 'ELF':
            #numofELF=numofELF+1
            val=Scanner.ELFScanner.ELFScan(i)
            result.update(val)
        if mime == 'MACHO':
            #numofMACHO=numofMACHO+1
            #print("machoscan")
            val=MachoScan(i)
            result.update(val)               
        if mime == 'JAR':
            #numofJar=numofJar+1
            val=Scanner.JarScanner.JarScan(i)
            result.update(val)
        if mime == 'PKG':
            #print(i)
            val = PKGScan(i)
            result.update(val)
            #print(i[6:])
            #print(val)
            #result[i[6:]] = val
    #print(result)
    return result
    #print(result)
    #finale=Utility.util.parseResult(result)
    #Utility.util.genReport(finale,scanfilename)
    #Utility.util.deleteTmp()    

def MachoScan(filepath):
    #print("machoscan")
    result={}
    fatbinaries=lief.MachO.parse(filepath,config=lief.MachO.ParserConfig.deep)
    n=len(fatbinaries)
    signed=True
    #print("fat")
    for i in range(n):
        binary=fatbinaries.at(i)
        try:
            signature=binary.code_signature
            signed=True 
        except:
            signed = False
            break
        try:            
            sig_dir=binary.code_signature_dir
            signed=True
        except:
            signed = False
            break
    if signed==False:
        result['unsigned']='yes'
    dep = True
    pie = True
    restricted = True
    canary = True
    arc = True
    
    for i in range(n):
        binary = fatbinaries.at(i)
        nx_enabled = HEADER_FLAGS.ALLOW_STACK_EXECUTION not in binary.header.flags_list
        pie_enabled = HEADER_FLAGS.PIE in binary.header.flags_list
        dep = dep and nx_enabled
        pie = pie and pie_enabled
        imported = binary.imported_functions
        canary_enabled = '___stack_chk_fail' in imported and '___stack_chk_guard' in imported
        canary = canary and canary_enabled
        arc_enabled = '_objc_release' in imported
        arc = arc and arc_enabled
        restricted_segment = False
        for segment in binary.segments:
            if segment.name.lower() == '__restrict':
                restricted_segment = True
                break
        restricted = restricted and restricted_segment
    if dep == False:       
        result['nx'] = 'no'
    if pie == False:
        result['pie'] = 'no'
    if canary == False:
        result['canary'] = 'no'
    if restricted == False:
        result['restricted'] = 'no'
    if arc == False:
        result['arc'] = 'no'
    os.remove(filepath)
    return {filepath[6: ]: result}

def IpaScan(path):
    gl.init()
    files=[]
    path1, _ = Utility.util.normalizePath(path)
    cmd = 'sh ./Utility/unarchieveipa.sh ' + path1
    os.system(cmd)  
    result={}        
    Utility.util.listFiles(path, files)
    #numofMACHO=0
    #print("finish script")
    for i in files:
        if i.split('/')[-1] == '.DS_Store':
            continue        
        mime=Utility.util.checkmime(i)
        if mime == 'PE':
            #numofPE=numofPE+1
            val=Scanner.PEScanner.PEScan(i)
            result.update(val)
        if mime == 'ELF':
            #numofELF=numofELF+1
            val=Scanner.ELFScanner.ELFScan(i)
            result.update(val)
        if mime == 'MACHO':
            #numofMACHO=numofMACHO+1
            #print("machoscan")
            val=MachoScan(i)
            result.update(val)               
        if mime == 'JAR':
            #numofJar=numofJar+1
            val=Scanner.JarScanner.JarScan(i)
            result.update(val)
        
            #print(i[6:])
            #print(val)
            #result[i[6:]] = val
    return result    
        

    
if __name__ == '__main__':
    p='/home/sphinx/Desktop/Citadel_ex/bash'
    p='/home/sphinx/Desktop/Citadel_ex/tmp/extracted/Uninstall Citrix Workspace.app/Contents/MacOS/Uninstall Citrix Workspace'
    print(MachoScan(p))