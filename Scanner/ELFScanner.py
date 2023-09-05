import os
import json
import Utility.globalvar as gl
import Utility.util
import Scanner.PEScanner
import Scanner.JarScanner
import Scanner.MachoScanner

    

def ELFScan(filepath):
    gl.init()
    fun=gl.getFun()
    checkpath = ''
    with open('Config/Env.txt','r') as fd:
        t=fd.readlines()
        for i in t:
            if i[:13]=='CHECKSECPATH=':
                checkpath = i[13:].split('\n')[0].split(' ')[0]
                
    try:
        if checkpath == '':            
            result=os.popen('checksec --file=%s --output=json' %filepath).read()
        else:
            result=os.popen('%s/checksec --file=%s --output=json' %(checkpath, filepath)).read()
        result=json.loads(result)
    except:
        print('checksec not found')
        return {}
    for key in result.keys():
        result=result[key]
        
       
    f=os.popen('readelf -s %s' %filepath).read().lower()
    result['dangerFun']=[]
    for i in fun:
        t=f.find(i)
        if t!=-1:
            result['dangerFun'].append(i)
    os.remove(filepath)
    return {filepath[6: ]: result}

def DebScan(path):
    #scanfilename=path.split('/')[-1]
    gl.init()
    files=[]
    path1, _ = Utility.util.normalizePath(path)
    cmd = 'sh ./Utility/unarchievedeb.sh ' + path1
    os.system(cmd)

    path=path + '/data'
    result={}
    
    Utility.util.listFiles(path, files)

    numofPE=0
    numofELF=0
    numofMACHO=0
    numofJar=0
    for i in files:
        mime=Utility.util.checkmime(i)
        if mime == 'PE':
            numofPE=numofPE+1
            val=Scanner.PEScanner.PEScan(i)
            result.update(val)
        if mime == 'ELF':
            numofELF=numofELF+1
            val=ELFScan(i)
            result.update(val)
        if mime == 'MACHO':
            numofMACHO=numofMACHO+1
            val=Scanner.MachoScanner.MachoScan(i)
            result[i[6:]]=val
        if mime == 'JAR':
            numofJar=numofJar+1
            val=Scanner.JarScanner.JarScan(i)
            result.update(val)
    return result    
    #print("%d %d %d" %(numofPE,numofELF, numofMACHO))
    #finale=Utility.util.parseResult(result)
    #Utility.util.genReport(finale,scanfilename)
    #Utility.util.deleteTmp()    

def RpmScan(path):
    #scanfilename=path.split('/')[-1]
    gl.init()
    files=[]
    path1, _ = Utility.util.normalizePath(path)
    cmd = 'sh ./Utility/unarchieverpm.sh ' + path1
    os.system(cmd)
    result={}
    
    Utility.util.listFiles(path, files)

    numofPE=0
    numofELF=0
    numofMACHO=0
    numofJar=0
    for i in files:
        mime=Utility.util.checkmime(i)
        if mime == 'PE':
            numofPE=numofPE+1
            val=Scanner.PEScanner.PEScan(i)
            result.update(val)
        if mime == 'ELF':
            numofELF=numofELF+1
            val=ELFScan(i)
            result.update(val)
        if mime == 'MACHO':
            numofMACHO=numofMACHO+1
            val=Scanner.MachoScanner.MachoScan(i)
            result[i[6:]]=val
        if mime == 'JAR':
            numofJar=numofJar+1
            val=Scanner.JarScanner.JarScan(i)
            result.update(val)
    return result    
if __name__ == '__main__':
    p='/home/sphinx/Desktop/XenDesktopVDA/opt/Citrix/VDA/bin/ctxaudi'
    ELFScanner(p)
