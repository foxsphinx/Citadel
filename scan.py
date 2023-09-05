import Scanner.PEScanner
import Scanner.ELFScanner
import Scanner.AndroidScanner
import Scanner.MachoScanner
import Scanner.DirScanner
import Utility.util
import sys
import os

def do_main():
    result = {}
    path=sys.argv[1]
    scanfilename = path.split('/')[-1]
    if os.path.exists("./tmp"):
        os.system('rm -rf ./tmp')
    os.system('mkdir ./tmp')
    os.system('cp -r %s ./tmp/' % path)    
    if os.path.isdir(sys.argv[1]):
        result = Scanner.DirScanner.DirScan("./tmp") 
        finale=Utility.util.parseResult(result)
        Utility.util.genReport(finale,scanfilename)
        Utility.util.deleteTmp()
        return        
    
    
    path = './tmp/' + scanfilename
    with open(path,'rb') as fd:
        magic=fd.read(21)
        suffix=path.split('.')[-1].lower()
    if magic == b'!<arch>\x0Adebian-binary' and suffix=='deb':
        result = Scanner.ELFScanner.DebScan(path)
        
    elif magic[:4] == b'\xED\xAB\xEE\xDB' and suffix == 'rpm':
        result = Scanner.ELFScanner.RpmScan(path)
        
    elif magic[:4] == b'PK\x03\x04' and  suffix=='apk':
        result = Scanner.AndroidScanner.AndroidScan(path)
        
    elif magic[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' and suffix=='msi':
        result = Scanner.PEScanner.MSIScan(path)
        
    elif magic[:4] == b'\x78\x01\x73\x0D' and suffix=='dmg':
        result = Scanner.MachoScanner.DMGScan(path)
        
    elif magic[:2]==b'MZ' and suffix in (None,'exe','dll'):
        result = Scanner.PEScanner.PEScan(path)
        
        result1 = {}
        name = path.split('/')[-1]
        length = len(path) - len(name)
        for key in result.keys():
            key1 = key[length:]
            result1[key1] = result[key]
        result = result1
    elif magic[:4] == b'xar!' and suffix == 'pkg':
        result = Scanner.MachoScanner.PKGScan(path)
    elif suffix == 'iso':
        result = Scanner.DirScanner.IsoScan(path)
    elif magic[:4] == b'PK\x03\x04' and  suffix=='ipa':
        result = Scanner.MachoScanner.IpaScan(path)
    elif magic[:4] == b'PK\x03\x04' and suffix == 'zip':
        result = Scanner.DirScanner.ZipScan(path)
    elif magic[:2] == b'\x1F\x8B' and suffix == 'gz':
        if path.split('.')[-2].lower() == 'tar':
            result = Scanner.DirScanner.TargzScan(path)
        else:
            print("This file is not supported, exit...")
            return
    else:
        print("This file is not supported, exit...")
        return
        
    finale=Utility.util.parseResult(result)
    Utility.util.genReport(finale,scanfilename)
    Utility.util.deleteTmp()
    return

  
    
if __name__== '__main__': 
    do_main()
    










