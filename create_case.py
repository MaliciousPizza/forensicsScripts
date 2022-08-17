import os,argparse,textwrap



def make_case_dir(c,n):
    new_dir = r'{}\{}\Case_working_folder'.format(c,n)
    # os.mkdir(new_dir)
    os.makedirs(new_dir)
    os.chdir(new_dir)
    os.makedirs('Images')
    os.makedirs('Tool_Suites')
    os.makedirs('Tool_Output')
    
#new_dir = r'{}\{}\Case_working_folder'.format(case_dir,case_number)
# os.mkdir(new_dir)

#print(new_dir)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Case directory creator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
        create_case.py "c:\Cases_folder\" case_number '''
        )
    )
    parser.add_argument('-c','--case_directory',type=str,help='Add the Case directory',required=True)
    parser.add_argument('-n','--case_number',type=str,help='Case Number',required=True)
    args = parser.parse_args()
    make_case_dir(args.case_directory,args.case_number)