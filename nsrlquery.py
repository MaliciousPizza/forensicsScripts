import sqlite3
import argparse,textwrap,pathlib
from nsrlmerge import NSRLMerge
import os

class HashCompare:
    def __init__(self,args):
        self.args = args
        

    def handle(self):
        if self.args.algorithm == 'md5':
            print(self.args.database)
            con = sqlite3.connect(self.args.database)
            cur = con.cursor()
            res = cur.execute('SELECT md5, application_type FROM FILE INNER JOIN pkg on pkg.package_id = file.package_id where md5 = ?',[self.args.hash] )
            query_output = res.fetchall()
            print(query_output)
        if self.args.algorithm == 'sha1':
            print(self.args.database)
            con = sqlite3.connect(self.args.database)
            cur = con.cursor()
            res = cur.execute('SELECT sha1, application_type FROM FILE INNER JOIN pkg on pkg.package_id = file.package_id where sha1 = ?',[self.args.hash] )
            query_output = res.fetchall()
            print(query_output)
        if self.args.algorithm == 'sha256':
            print(self.args.database)
            con = sqlite3.connect(self.args.database)
            cur = con.cursor()
            res = cur.execute('SELECT sha256, application_type FROM FILE INNER JOIN pkg on pkg.package_id = file.package_id where sha256 = ?',[self.args.hash] )
            query_output = res.fetchall()
            print(query_output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description= 'RDSV3 Query Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
            nsrlquery.py -a sha256 -d /nsrl/rdsv3.db 000000ADA6DDCA899E68D00512489768A1A330CBB02716CEC3BD73FE36B28DE7
            nsrlquery.py -m /nsrl/databases/
        ''')
    )
    # parser.add_argument('-m','--merge',type=str,help='Directory where the NSRL Databases exist to Merge NSRL')
    parser.add_argument('-a','--algorithm',type=str,help='sha256, md5, sha1',default='md5')
    parser.add_argument('-d','--database',type=str,help='directory to the sqlite3 database')
    parser.add_argument('hash',type=str)
    args = parser.parse_args()

    h = HashCompare(args)
    h.handle()
