import os
import sys
def JarScan(path):
    result={}
    javapath=os.getenv('JAVA_HOME')
    if javapath == None:
        with open('Config/Env.txt','r') as fd:
            t=fd.readlines()
            for i in t:
                if i[:10]=='JAVA_HOME=':
                    javapath=i[10:].split('\n')[0].split(' ')[0]
    if javapath == None:
        print('JAVA_HOME is not set')
        return {}
    out=os.popen('%s/bin/jarsigner -verify %s' %(javapath,path)).read()
    p1=out.find('certificate is self-signed')
    if p1 != -1:
        result['selfsigned'] = 'yes'
    p1=out.find('certificate chain is invalid')
    if p1 != -1:
        result['invalidchain'] = 'yes'
    p1=out.find('jar is unsigned')
    if p1 != -1:
        result['nosignature']='yes'
    return {path[6: ]: result}

if __name__ == '__main__':
    path='/home/sphinx/Desktop/Citadel_ex/test/opt/Citrix/VDA/lib64/annotations-3.0.1u2.jar'
    #path1='/home/sphinx/Desktop/Citadel_ex/Citrix_Workspace_20_6_5.apk'
    o1=JarScan(path)
    print(o1)
    #o2=JarScan(path1)
    
