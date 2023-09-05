import os
import Utility.globalvar as gl


def parseResult(result):
    #print(result)
    gl.init()
    fun=gl.getFun()
    relro=[]
    relropart=[]
    canary=[]
    nx=[]
    pie=[]
    rpath=[]
    symbols=[]
    nosignature=[]
    dangerFun={}
    arc = []
    cfg = []
    dynamicBase = []
    forceIntegrity = []
    highEntropyVA = []
    isolation = []
    rfg = []
    safeSEH = []
    seh = []
    dangerPerm = []
    exportedActivity = []
    exportedActivityAlias = []
    exportedProvider = []
    exportedReceiver = []
    exportedService = []
    signaturePerm = []
    user_permission = []
    selfsigned = []
    invalidchain = []
    native=0
    for i in fun:
        dangerFun[i]=[]
    
    
    finale={}
    for key in result:
        value=result[key]
        if value is None:
            continue
        if 'relro' in value.keys():
            if value['relro'] == 'no':
                relro.append(key)
            elif value['relro'] == 'partial':
                relropart.append(key)
        if 'canary' in value.keys():
            if value['canary'] != 'yes':
                canary.append(key)
        if 'nx' in value.keys():
            if value['nx'] != 'yes':
                nx.append(key)
        if 'pie' in value.keys():
            if value['pie'] not in ['yes','dso']:
                pie.append(key)
        if 'rpath' in value.keys():
            if value['rpath'] != 'no':
                rpath.append(key)
        if 'symbols' in value.keys():
            if value['symbols'] != 'no':
                symbols.append(key)
        if 'native' in value.keys():
            if value['native'] != 'no':
                native=native+1        
        if 'unsigned' in value.keys():
            if value['unsigned'] == 'yes':
                nosignature.append(key)
        if 'arc' in value.keys():
            if value['arc'] == 'no':
                arc.append(key)
        if 'cfg' in value.keys():
            if value['cfg'] == 'no':
                cfg.append(key)
        if 'dynamicBase' in value.keys():
            if value['dynamicBase'] == 'no':
                dynamicBase.append(key)
        if 'forceIntegrity' in value.keys():
            if value['forceIntegrity'] == 'no':
                forceIntegrity.append(key)
        if 'highEntropyVA' in value.keys():
            if value['highEntropyVA'] == 'no':
                highEntropyVA.append(key)
        if 'isolation' in value.keys():
            if value['isolation'] == 'no':
                isolation.append(key)
        if 'rfg' in value.keys():
            if value['rfg'] == 'no':
                rfg.append(key)
        if 'safeSEH' in value.keys():
            if value['safeSEH'] == 'no':
                safeSEH.append(key)
        if 'seh' in value.keys():
            if value['seh'] == 'no':
                seh.append(key)
        if 'dangerPerm' in value.keys():
            if value['dangerPerm'] == 'yes':
                dangerPerm.append(key)
        if 'exportedActivity' in value.keys():
            if value['exportedActivity'] == 'yes':
                exportedActivity.append(key)
        if 'exportedActivityAlias' in value.keys():
            if value['exportedActivityAlias'] == 'yes':
                exportedActivityAlias.append(key)
        if 'exportedProvider' in value.keys():
            if value['exportedProvider'] == 'yes':
                exportedProvider.append(key)
        if 'exportedReceiver' in value.keys():
            if value['exportedReceiver'] == 'yes':
                exportedReceiver.append(key)
        if 'exportedService' in value.keys():
            if value['exportedService'] == 'yes':
                exportedService.append(key)        
        if 'signaturePerm' in value.keys():
            if value['signaturePerm'] == 'yes':
                signaturePerm.append(key)
        if 'user_permission' in value.keys():
            if value['user_permission'] == 'yes':
                user_permission.append(key)                
        if 'selfsigned' in value.keys():
            if value['selfsigned'] == 'yes':
                selfsigned.append(key)
        if 'invalidchain' in value.keys():
            if value['invalidchain'] == 'yes':
                invalidchain.append(key)
                                
                
        if 'dangerFun' in value.keys():
            for i in fun:
                if i in value['dangerFun']:
                    dangerFun[i].append(key)
            
    finale['relro']=relro
    finale['relropart']=relropart
    finale['canary']=canary
    finale['nx']=nx
    finale['pie']=pie
    finale['rpath']=rpath
    finale['symbols']=symbols
    finale['nosignature']=nosignature
    finale['arc'] = arc
    finale['cfg'] = cfg
    finale['dynamicBase'] = dynamicBase
    finale['forceIntegrity'] = forceIntegrity
    finale['highEntropyVA'] = highEntropyVA
    finale['isolation'] = isolation
    finale['rfg'] = rfg
    finale['safeSEH'] = safeSEH
    finale['seh'] = seh
    finale['dangerFun']=dangerFun
    finale['dangerPerm']=dangerPerm
    finale['exportedActivity']=exportedActivity
    finale['exportedActivityAlias']=exportedActivityAlias
    finale['exportedProvider']=exportedProvider
    finale['exportedReceiver']=exportedReceiver
    finale['exportedService']=exportedService
    finale['signaturePerm']=signaturePerm
    finale['user_permission']=user_permission
    finale['selfsigned']=selfsigned
    finale['invalidchain']=invalidchain
    return finale


def genReport(result,path):
    #print(result)
    fun=gl.getFun()
    header='''<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<title>test</title>
</head>

<body>'''
    tail='''</body>
</html>'''
    body=''
    emptykey=[]
    for key in result:
        if result[key] == []:
            emptykey.append(key)
    for key in emptykey:
        result.pop(key)
    for key in result:
        if key == 'dangerFun':
            values=result[key]
            emptykey=[]
            for key in values:
                if values[key] == []:
                    emptykey.append(key)
            for key in emptykey:
                values.pop(key)  
            if result['dangerFun'] == {}:
                continue
            body=body+'<h1>Banned functions are used:</h1>'
            
            for k in values:
                body=body+'<h2>&nbsp;&nbsp;&nbsp;&nbsp;'+k+'</h2>'
                for v in values[k]:
                    body=body+'<li>&nbsp;&nbsp;&nbsp;&nbsp;'+v+'</li>'
            continue
        #if key == 'selfsigned' and result[key] == 'yes':
            #body=body+'<h1>Certificate is self-signed</h1>'
            #continue
        #if key == 'invalidchain' and result[key] == 'yes':
            #body=body+"<h1>Certificate's chain is invalid</h1>"
            #continue  
        
        #if key == "unsigned" and result[key] == 'yes':
            #body=body+"<h1>Package not signed</h1>"
            #continue
            
        if key =="dangerPerm":
            body=body+"<h1>Danger Level Permission Defined:</h1>"
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
            continue
                
        if key =="normPerm":
            body=body+"<h1>Normal Level Permission Defined:</h1>"
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
            continue
                
        if key =="exportedActivity":
            body=body+"<h1>Activity exported without signature level or above permission control:</h1>"
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'  
            continue
                
        if key =="exportedActivityAlias":
            body=body+"<h1>Activity-alias exported without signature level or above permission control:</h1>"
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
            continue
                
        if key =="exportedReceiver":
            body=body+"<h1>Receiver exported without signature level or above permission control:</h1>"
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'                 
            continue
        
        if key =="exportedProvider":
            body=body+"<h1>Provider exported without signature level or above permission control:</h1>"
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'         
            continue
        
        if key =="exportedService":
            body=body+"<h1>Service exported without signature level or above permission control:</h1>"
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'  
            continue
            
        if key == 'relro':
            body=body+'<h1>relro is not enabled:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'            
        elif key == 'relropart':
            body=body+'<h1>relro is only partial enabled:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'            
        elif key == 'canary':
            body=body+'<h1>stack canary is not enabled:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'            
        elif key == 'nx':
            body=body+'<h1>NX is not enabled:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'            
        elif key == 'pie':
            body=body+'<h1>ASLR capability is not enabled:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'            
        elif key == 'rpath':
            body=body+'<h1>rpath is used:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'            
        elif key == 'symbols':
            body=body+'<h1>Contain debug symbols:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'nosignature':
            body=body+'<h1>No signature:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'selfsigned':
            body=body+'<h1>Self-signed signature:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'invalidchain':
            body=body+'<h1>Certificate keychains for signature is invalid:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'                
                
        elif key == 'arc':
            body=body+'<h1>No arc:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'cfg':
            body=body+'<h1>No cfg:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'dynamicBase':
            body=body+'<h1>No dynamicBase:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'forceIntegrity':
            body=body+'<h1>No forceIntegrity:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'forceIntegrity':
            body=body+'<h1>No forceIntegrity:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'highEntropyVA':
            body=body+'<h1>No highEntropyVA:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'isolation':
            body=body+'<h1>No isolation:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'rfg':
            body=body+'<h1>No rfg:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'safeSEH':
            body=body+'<h1>No safeSEH:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'
        elif key == 'seh':
            body=body+'<h1>No seh:</h1>'
            values=result[key]
            for val in values:
                body=body+'<li>'+val+'</li>'                
        
            
           
    name="%s_report.html" %path
    with open(name,'w') as fd:
        fd.writelines(header)
        fd.writelines(body)
        fd.writelines(tail)
    
def deleteTmp():
    os.system('rm -rf tmp/')
    
def listFiles(path,files):
    for root,dir,file in os.walk(path):
        for f in file:
            if not os.path.islink(os.path.join(root,f)):
                files.append(os.path.join(root,f))

def normalizePath(pathfile):
    path = pathfile.split(' ')
    newpath = ''
    if len(path) != 1:
        for i in range(len(path) - 1):
            newpath = newpath + path[i] + '\ '
        newpath = newpath + path[-1]
    else:
        newpath = pathfile
            
    pkgname =newpath.split('/')[-1]
    return (newpath, pkgname)
        
def checkmime(filepath):
    with open(filepath,'rb') as fd:
        magic = fd.read(5)
        suffix=filepath.lower().split('/')[-1].split('.')
        if len(suffix)==1:
            suffix=None
        else:
            suffix=suffix[-1]
        
        if magic[:2]==b'MZ' and suffix in (None,'exe','dll'):
            return 'PE'
        if magic[:4] == b'\x7FELF': #cwal has some files with dll suffix but are .so files
            return 'ELF'
        if magic[:4] == b'\xCF\xFA\xED\xFE' and suffix in (None, 'dylib'):
            return 'MACHO'
        if magic[:4] == b'PK\x03\x04' and suffix == 'jar':
            return 'JAR'
        if magic[:4] == b'\xCA\xFE\xBA\xBE' and suffix in (None, 'dylib'):
            return 'MACHO'
        if magic[:4] == b'xar!' and suffix == 'pkg':
            return 'PKG'
        if magic[:4] == b'\xD0\xCF\x11\xE0' and suffix == 'msi':
            return 'MSI'
        if magic[:4] == b'MSCF' and suffix == 'cab':
            return 'CAB'
        if magic == b'!<arch>\x0Adebian-binary' and suffix=='deb':
            return 'DEB'            
        if magic[:4] == b'\xED\xAB\xEE\xDB' and suffix == 'rpm':
            return 'RPM'
        if suffix == 'dmg':
            return 'DMG'
        if suffix == 'iso':
            return 'ISO'
        if magic[:4] == b'PK\x03\x04' and  suffix=='ipa':
            return 'IPA'
        if magic[:4] == b'PK\x03\x04' and suffix == 'zip':
            return 'ZIP'
        if magic[:2] == b'\x1F\x8B' and suffix == 'gz':
            return 'TARGZ'
        elif magic[:4] == b'PK\x03\x04' and  suffix=='apk':
            return 'APK'       
