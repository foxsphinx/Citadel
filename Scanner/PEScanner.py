import os
import json
import Utility.globalvar as gl
import Utility.util
import Scanner.JarScanner
#path='/home/sphinx/Desktop/keygen.exe'
#path='/home/sphinx/Desktop/Citadel_ex/test/opt/Citrix/VDA/lib64/CodeProject.ObjectPool.dll'
def run_winchecksec(path, checkpath):
    tmp = path.split(' ')
    newpath = ''
    if len(tmp) != 0:
        for i in range(len(tmp) - 1):
            if tmp[i][-1] != "\\":
                newpath = newpath + tmp[i] + '\\ '
        newpath = newpath + tmp[-1]
    else:
        newpath = path
    path = newpath
    if checkpath == '':            
        result=os.popen('winchecksec -j %s' %path).read()
    else:
        result=os.popen('%s/winchecksec -j %s' %(checkpath, path)).read()
    result=json.loads(result)
    result = result[0]['mitigations']
    returnval = {}
    for key in result.keys():
        if key == 'gs' and result['gs']['presence'] == 'NotPresent':
            returnval['canary'] = 'no'
            continue
        if key == 'aslr' and result['aslr']['presence'] == 'NotPresent':
            returnval['pie'] = 'no'
            continue
        if key == 'authenticode' and result['authenticode']['presence'] == 'NotPresent':
            returnval['unsigned'] = 'yes'
            continue            
        if result[key]['presence'] ==  'NotPresent':
            returnval[key] = 'no'
    return returnval

def PEScan(path):
    gl.init()
    fun=gl.getFun()
    checkpath = ''
    result = {}
    with open('Config/Env.txt','r') as fd:
        t=fd.readlines()
        for i in t:
            if i[:16]=='WINCHECKSECPATH=':
                checkpath = i[16:].split('\n')[0].split(' ')[0]
    try:
        returnval = run_winchecksec(path, checkpath)
        result[path[6:]] = returnval
    except:
        print('checksec not found')
        return {}
    if path[-4:] == '.exe':
        newpath,_ = Utility.util.normalizePath(path)
        path, newpath = newpath, path
        os.system("mv %s %s.bak" % (path, path))           
        os.system("mkdir %s" % path)
        os.system("mv %s.bak %s/%s" % (path, path, path.split("/")[-1]))
        os.system('cd %s && 7z x %s && cd ..' %(path, path.split("/")[-1]))
        os.system('rm -f '+path+'/'+path.split("/")[-1])
        path, newpath = newpath, path
        files = []
        Utility.util.listFiles(path, files)
        for file in files:
            mime = Utility.util.checkmime(file)
            if mime == 'PE':
                result.update(PEScan(file))
                #os.removedirs(file)
            elif mime == 'JAR':
                result.update(Scanner.JarScanner.JarScan(file))
                os.remove(file)
            elif mime == 'MSI':
                result.update(MSIScan(file))
                #os.remove(file)
            elif mime == 'CAB':
                result.update(CABScan(file))
                #os.remove(file)
    #os.system("rm -rf %s" %path[:-4])
    
    return result
    #try:
        #pe=pefile.PE(path)
    #except:
        #return 
    #result={}
    
    #if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress !=0 :
        #result.update({"native" : "no"} )
    #else:
        #result.update({"native" : "yes"})
               
    
    #if pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        #result.update({"pie":"yes"})
        
    #else:
        #result.update({"pie":"no"})
        
    
    #NX=True
    #for i in pe.sections:
        #if i.IMAGE_SCN_MEM_WRITE and i.IMAGE_SCN_MEM_EXECUTE:
            #NX=False
    #if NX:
        #result.update({"nx":"yes"})
    #else:
        #result.update({"nx":"no"})
        
    #f=os.popen('osslsigncode verify %s' %path).read().lower()
    #f=f.split('\n')[-2]
    #if f != 'succeeded':
     #   returnval.update({'unsigned':'yes'})
    #print(returnval)
    
def CABScan(path):
    newpath,_  = Utility.util.normalizePath(path)
    path, newpath = newpath, path    
    os.system("mv %s %s.bak" % (path, path))           
    os.system("mkdir %s" % path)
    os.system("mv %s.bak %s/%s" % (path, path, path.split("/")[-1]))
    os.system('cd %s && 7z x %s && cd ..' %(path, path.split("/")[-1]))
    os.system('rm -f '+path+'/'+path.split("/")[-1])
    path, newpath = newpath, path 
    files = []
    Utility.util.listFiles(path, files)
    result = {}
    for file in files:
        mime = Utility.util.checkmime(file)
        if mime == 'PE':
            tmp = PEScan(file)
            #print(tmp)
            result.update(tmp)
            #os.remove(file)
        elif mime == 'JAR':
            result.update({file: Scanner.JarScanner.JarScan(file)})
            #os.remove(file)
        elif mime == 'MSI':
            result.update(MSIScan(file))
            #os.remove(file)
        elif mime == 'CAB':
            result.update(CABScan(file))
            #os.removedirs(file)
    
    return result        
    

def MSIScan(path):
    """"""
    result1 = {}
    with open('Config/Env.txt','r') as fd:
        t=fd.readlines()
        for i in t:
            if i[:16]=='OSSLSIGNCODE=':
                checkpath = i[13:].split('\n')[0].split(' ')[0]
    try:
        if checkpath == '':   
            f=os.popen('osslsigncode verify %s' %path).read().lower()
        else:
            f=os.popen('%s/osslsigncode verify %s' %(checkpath, path)).read().lower()            
        f=f.split('\n')[-1]
        if f != 'succeeded':
            result1['nosignature'] = 'yes'
        else:
            result1['nosignature'] = 'no'        
    except:
        print('osslsigncode cannot be found!')
        result1 = {}

    result = {}
    result[path[6:]] = result1
    newpath,_  = Utility.util.normalizePath(path)
    path, newpath = newpath, path    
    os.system("mv %s %s.bak" % (path, path))           
    os.system("mkdir %s" % path)
    os.system("mv %s.bak %s/%s" % (path, path, path.split("/")[-1]))
    os.system("msiextract %s -C %s" % (path+'/'+path.split("/")[-1], path))
    os.system('rm -f '+path+'/'+path.split("/")[-1])
    path, newpath = newpath, path    
    files = []
    Utility.util.listFiles(path, files)
    for file in files:
            mime = Utility.util.checkmime(file)
            if mime == 'PE':
                tmp = PEScan(file)
                #print(tmp)
                result.update(tmp)
                #os.removedirs(file)
            elif mime == 'JAR':
                result.update({file: Scanner.JarScanner.JarScan(file)})
                os.remove(file)
            elif mime == 'MSI':
                result.update(MSIScan(file))
                #os.removedirs(file)
            elif mime == 'CAB':
                result.update(CABScan(file))
                #os.remove(file)
    #os.system("rm -rf %s" %path[:-4] )
    return result
    
if __name__=='__main__':
    print(PEScan(path))
    
