import enum
import os,sys,argparse,hashlib,textwrap
from os import path,walk,stat
from os.path import splitext,basename,join,dirname,getsize,getatime,getctime,getmtime

def hash_type(m,hashtype):
    BLOCKSIZE = 65536
    if hashtype == 'md5':
        hash = hashlib.md5()
    else:
        hash = hashlib.sha256()
    with open(m,'rb') as file_to_hash:
        while True:
            buffer = file_to_hash.read(BLOCKSIZE)
            if not buffer:
                break
            hash.update(buffer)
    return hash.hexdigest()

class Hash:
    def __init__(self,args):
        self.args = args

    def handle(self):
        if self.args.algorithm == 'md5':
            for path,currentDirectory,files in walk(self.args.directory):
                for file in files:
                    file_to_hash = join(path,file)
                    hashed_file = hash_type(file_to_hash,'md5')
                    with open(self.args.write,'a+') as f:
                        f.write('{}\t{}\n'.format(file_to_hash,hashed_file))
        elif self.args.algorithm == 'sha256':
            for path,currentDirectory,files in walk(self.args.directory):
                for file in files:
                    file_to_hash = join(path,file)
                    hashed_file = hash_type(file_to_hash,'sha256')
                    with open(self.args.write, 'a+') as f:
                        f.write('{}\t{}\n'.format(file_to_hash,hashed_file))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='hash all of your docs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
        hashy.py -md5 -w output_file.txt -d /directory/to/hash''')

    )
    parser.add_argument('-a','--algorithm',type=str,help='sha256 or md5',required=True)
    #parser.add_argument('-sha256','--sha256',action='store_true',help='Sha256 hash')
    parser.add_argument('-w','--write',type=str,help='output file to print to')
    parser.add_argument('-d','--directory',type=str,help='the directory to hash')
    args = parser.parse_args()

    h = Hash(args)
    h.handle()

