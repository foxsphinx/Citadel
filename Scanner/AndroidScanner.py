import os
import Utility.globalvar as gl
import Utility.util
import Scanner.JarScanner
import Scanner.ELFScanner
from xml.dom.minidom import parse
import xml.dom.minidom


def AndroidScan(path):
    gl.init()
    fun=gl.getFun()
    files=[]
    Result=Scanner.JarScanner.JarScan(path)
    path1, name = Utility.util.normalizePath(path)
    cmd = 'sh ./Utility/unarchieveapk.sh ' + path1
    os.popen(cmd).read()
    print('scanning manifest')
    tmpRes=ManifestScan('%s/%s/AndroidManifest.xml' %(path, name[:-4]), path)
    Result.update(tmpRes)
    libpath='%s/lib' % path
    print('scanning binaries')
    Utility.util.listFiles(libpath, files)
    tmpRes={}
    for f in files:
        Result.update(Scanner.ELFScanner.ELFScan(f))
    Result.update(tmpRes)
    return Result  
    
def ManifestScan(path, name):
    result={}
    DOMTree=xml.dom.minidom.parse(path)
    manifest=DOMTree.documentElement
    
    #permission usage check
    userPerms=manifest.getElementsByTagName('uses-permission')
    perms=[]
    for p in userPerms:
        if p.hasAttribute('android:name'):
            perms.append(p.getAttribute('android:name'))
    result['user-permission']=perms
    
    #permission defined check
    normPerm=[]
    dangerPerm=[]
    signaturePerm=[]
    systemPerm=[]
    defPerms=manifest.getElementsByTagName('permission')
    for p in defPerms:
        if p.hasAttribute('android:protectionLevel'):
            level=p.getAttribute('android:protectionLevel')
            if level=='normal':
                normPerm.append(p.getAttribute('android:name'))
            elif level=='dangerous':
                dangerPerm.append(p.getAttribute('android:name'))
            elif level=='signature':
                signaturePerm.append(p.getAttribute('android:name'))
            elif level in ('signatureOrSystem' ,'signature|privileged'):
                systemPerm.append(p.getAttribute('android:name'))
        else:
            normPerm.append(p.getAttribute('android:name'))
        if normPerm != []:
            result['normPerm']=normPerm
        if dangerPerm !=[]:
            result['dangerPerm']=dangerPerm
        if signaturePerm !=[]:
            result['signaturePerm']=signaturePerm
        if systemPerm != []:
            result['systemPerm']=systemPerm
            
            
    #checking allowBackup and debuggable    
    applications=manifest.getElementsByTagName('application')
    for application in applications:
        if application.hasAttribute('android:allowBackup'):
            if application.getAttribute('android:allowBackup') == 'true':
                result['allowBackup']='yes'
        if application.hasAttribute('android:debuggable'):
            if application.getAttribute('android:debuggable') == 'true':
                result['debuggable']='yes'
    
    #get exported activity
    exportedActivity=[]        
    activities=application.getElementsByTagName('activity')
    for activity in activities:
        if activity.hasAttribute('android:enabled'):
            if activity.getAttribute('android:enabled') == 'false':
                continue        
        exported='false'
        intentFilter=activity.getElementsByTagName('intent-filter')
        if intentFilter !=[]:
            exported='true'
        if activity.hasAttribute('android:exported'):
            exported=activity.getAttribute('android:exported') 
        if activity.hasAttribute('android:permission'):
            perm=activity.getAttribute('android:permission')
            if (perm in signaturePerm) or (perm in systemPerm):
                continue            
        if ((intentFilter == [] and exported == 'true') or (intentFilter != [] and exported != 'false')):
            exportedActivity.append(activity.getAttribute('android:name'))
    result['exportedActivity']=exportedActivity
    
    #get exported receiver
    exportedReceiver=[]        
    receivers=application.getElementsByTagName('receiver')
    for receiver in receivers:
        if receiver.hasAttribute('android:enabled'):
            if receiver.getAttribute('android:enabled') == 'false':
                continue        
        exported='false'
        intentFilter=receiver.getElementsByTagName('intent-filter')
        if intentFilter !=[]:
            exported='true'
        if receiver.hasAttribute('android:exported'):
            exported=receiver.getAttribute('android:exported')  
        if receiver.hasAttribute('android:permission'):
            perm=receiver.getAttribute('android:permission')
            if (perm in signaturePerm) or (perm in systemPerm):
                continue            
        if ((intentFilter == [] and exported == 'true') or (intentFilter != [] and exported != 'false')):
            exportedReceiver.append(receiver.getAttribute('android:name'))
    result['exportedReceiver']=exportedReceiver
    
    #get exported service
    exportedService=[]        
    services=application.getElementsByTagName('service')
    for service in services:
        if service.hasAttribute('android:enabled'):
            if service.getAttribute('android:enabled') == 'false':
                continue        
        exported='false'
        intentFilter=service.getElementsByTagName('intent-filter')
        if intentFilter !=[]:
            exported='true'
        if service.hasAttribute('android:exported'):
            exported=service.getAttribute('android:exported')
        if service.hasAttribute('android:permission'):
            perm=service.getAttribute('android:permission')
            if (perm in signaturePerm) or (perm in systemPerm):
                continue            
        if ((intentFilter == [] and exported == 'true') or (intentFilter != [] and exported != 'false')):
            exportedService.append(service.getAttribute('android:name'))
    result['exportedService']=exportedService
    
    #get exported provider
    exportedProvider=[]        
    providers=application.getElementsByTagName('provider')
    for provider in providers:
        if provider.hasAttribute('android:enabled'):
            if provider.getAttribute('android:enabled') == 'false':
                continue        
        exported='false'
        intentFilter=provider.getElementsByTagName('intent-filter')
        if intentFilter !=[]:
            exported='true'
        if provider.hasAttribute('android:exported'):
            exported=provider.getAttribute('android:exported')
        if provider.hasAttribute('android:permission'):
            perm=provider.getAttribute('android:permission')
            if (perm in signaturePerm) or (perm in systemPerm):
                continue        
        if ((intentFilter == [] and exported == 'true') or (intentFilter != [] and exported != 'false')):
            exportedProvider.append(provider.getAttribute('android:name'))
    result['exportedProvider']=exportedProvider
    
    #get exported activity-alias
    exportedActivityAlias=[]        
    aaliases=application.getElementsByTagName('activity-alias')
    for aalias in aaliases:
        if aalias.hasAttribute('android:enabled'):
            if aalias.getAttribute('android:enabled') == 'false':
                continue
                
            
        exported='false'
        intentFilter=aalias.getElementsByTagName('intent-filter')
        if intentFilter !=[]:
            exported='true'
        if aalias.hasAttribute('android:exported'):
            exported=aalias.getAttribute('android:exported') 
        if aalias.hasAttribute('android:permission'):
            perm=aalias.getAttribute('android:permission')
            if (perm in signaturePerm) or (perm in systemPerm):
                continue
        if ((intentFilter == [] and exported == 'true') or (intentFilter != [] and exported != 'false')):
            exportedActivityAlias.append('%s  ->  %s' %(aalias.getAttribute('android:name'),aalias.getAttribute('android:targetActivity')))
    result['exportedActivityAlias']=exportedActivityAlias
    issueComponents = []
    for key in result:
        for comp in result[key]:
            if comp not in issueComponents:
                issueComponents.append(comp)
    result1 = {}
    for i in issueComponents:
        result1.update({'%s/%s' %(name[6:], i): {}})
    for i in issueComponents:
        if i in result['dangerPerm']:
            result1['%s/%s' %(name[6:], i)]['dangerPerm'] = 'yes'
        if i in result['exportedActivity']:
            result1['%s/%s' %(name[6:], i)]['exportedActivity'] = 'yes'
        if i in result['exportedActivityAlias']:
            result1['%s/%s' %(name[6:], i)]['exportedActivityAlias'] = 'yes'
        if i in result['exportedProvider']:
            result1['%s/%s' %(name[6:], i)]['exportedProvider'] = 'yes'
        if i in result['exportedReceiver']:
            result1['%s/%s' %(name[6:], i)]['exportedReceiver'] = 'yes'
        if i in result['exportedService']:
            result1['%s/%s' %(name[6:], i)]['exportedService'] = 'yes'
        if i in result['signaturePerm']:
            result1['%s/%s' %(name[6:], i)]['signaturePerm'] = 'yes'
        if i in result['user-permission']:
            result1['%s/%s' %(name[6:], i)]['user_permission'] = 'yes'            
    return result1
    