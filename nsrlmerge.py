import sqlite3
import os
import argparse
import textwrap

class NSRLMerge:

    def __init__(self,args):
        self.args = args

    def merge_databases(self,db1,db2):
        self.db1 = db1
        self.db2 = db2
        con3 = sqlite3.connect(self.db1)

        con3.execute("ATTACH '" + self.db2 +  "' as dba")

        con3.execute("BEGIN")
        for row in con3.execute("SELECT * FROM dba.sqlite_master WHERE type='table'"):
            combine = "INSERT OR IGNORE INTO "+ row[1] + " SELECT * FROM dba." + row[1]
            print(combine)
            con3.execute(combine)
        con3.commit()
        con3.execute("detach database dba")


    def read_files(self,directory):
        self.directory = directory
        fname = []
        for root,d_names,f_names in os.walk(self.args.directory):
            for f in f_names:
                c_name = os.path.join(root, f)
                filename, file_extension = os.path.splitext(c_name)
                if (file_extension == '.db'):
                    fname.append(c_name)

        return fname

    def batch_merge(self):
        db_files = merge.read_files(self.args.directory)
        for db_file in db_files[1:]:
            merge.merge_databases(db_files[0], db_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description= 'RDSV3 Merge Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
            nsrlmerge.py -d /RDSV3/SQLite/NSRL/
        ''')
    )

    parser.add_argument('-dir','--directory',type=str,help='directory to the sqlite3 databases to merge',required=True)
    args = parser.parse_args()


    merge = NSRLMerge(args)
    merge.batch_merge()