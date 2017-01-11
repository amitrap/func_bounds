import os
from commands import getstatusoutput
from os.path import dirname, realpath, join as path_join, basename
import subprocess
import time
import re
import argparse


BINARIES_NAME_PATTERN = "^.*"
FNULL = open(os.devnull, 'w')


def run_command_async(cmdline):
    print "Executing %s" % cmdline
    p = subprocess.Popen(cmdline.split())
    return p


def generate_all_bounds(args, binpath):
    scripts_root = dirname(realpath(__file__))
    ida_func_bound_path = path_join(scripts_root, "ida_func_bounds.py")
    dirpath, dirnames, filenames = os.walk(binpath).next()
    if os.name == 'nt':
        p_list = []
        for name in filenames:
            if name.endswith(r".bounds.auto.py") or not re.match(BINARIES_NAME_PATTERN, name):
                continue
            ida_cmd_line = '{} -B -S"{}" {}'.format(args['idal64_path'], ida_func_bound_path,
                                                    realpath(path_join(dirpath, name)))
            p_list.append(run_command_async(ida_cmd_line))
        raw_input("IDA Finished parsing ALL?")
        for p in p_list:
            try:
                p.terminate()
            except:
                pass
    elif os.name == 'posix':
        for name in filenames:
            if name.endswith(r".bounds.auto.py") or not re.match(BINARIES_NAME_PATTERN, name):
                continue
            print "Extracting procedures from {} with IDA".format(realpath(path_join(dirpath, name)))
            extract_command = 'cd {};TVHEADLESS=1 {} -B -S"{}" {} > {}'. \
                format(dirpath, args['idal64_path'], ida_func_bound_path,
                       realpath(path_join(dirpath, name)), FNULL.name)
            r, output = getstatusoutput(extract_command)
            if r != 0:
                raise Exception("IDA extract command ({}) returned code {}.".format(extract_command, r))


def delete_all_temps(binpath, ext_list):
    dirpath, dirnames, filenames = os.walk(binpath).next()
    for name in filenames:
        for ext in ext_list:
            if name.endswith(ext):
                os.unlink(path_join(dirpath, name))


def regenerate_all_bounds(args, binpath):
    temp_exts = [".id0", ".id1", ".id2", ".til", ".nam", ".i64"]
    delete_all_temps(binpath, temp_exts)
    generate_all_bounds(args, binpath)
    # time.sleep(5)
    delete_all_temps(binpath, temp_exts)


def compare_all_bounds(unstripped_path, stripped_path):
    undiscovered_count = 0
    unstripped_count = 0

    dirpath, dirnames, filenames = os.walk(unstripped_path).next()
    for name in filenames:
        if not (name.endswith(r".bounds.auto.py") and re.match(BINARIES_NAME_PATTERN, name)):
            continue
        try:
            unstripped_func_bounds_file_path = path_join(unstripped_path, name)
            stripped_func_bounds_file_path = path_join(stripped_path, name)

            print "Parsing bounds for unstripped=%s stripped=%s" % (
            unstripped_func_bounds_file_path, stripped_func_bounds_file_path)

            unstripped_bounds_dict, unstripped_names_dict = tuple(
                eval(file(unstripped_func_bounds_file_path, "rb").read()))
            stripped_bounds_dict, stripped_names_dict = tuple(eval(file(stripped_func_bounds_file_path, "rb").read()))

            unstripped_bounds_dict = {k: frozenset(unstripped_bounds_dict[k]) for k in unstripped_bounds_dict.keys()}
            stripped_bounds_dict = {k: frozenset(stripped_bounds_dict[k]) for k in stripped_bounds_dict.keys()}

            undiscovered_func_bounds = frozenset(unstripped_bounds_dict.items()) - frozenset(
                stripped_bounds_dict.items())

            unstripped_count += len(unstripped_bounds_dict)
            undiscovered_count += len(undiscovered_func_bounds)
        except IOError:
            pass

    print 'Results for files with pattern "%s" is: (undiscovered count/func count) (%d/%d), %f%%' % (
    BINARIES_NAME_PATTERN, undiscovered_count, unstripped_count, (float(undiscovered_count) / unstripped_count) * 100.0)


def main():
    parser = argparse.ArgumentParser(description="Evaluate IDA's ability to detect stripped procedures.")
    default_idal64_path = {'nt': 'C:\Program Files (x86)\IDA 6.4\idaq.exe', 'posix': "/opt/ida-6.95/idal64"}[os.name]
    parser.add_argument('--idal64-path', default=default_idal64_path, type=str,
                        help="Path to the idal64 executable (default={})".format(default_idal64_path))
    default_bin_path = "../Data" if os.getcwd().endswith('Src') else "Data"
    parser.add_argument('--bin-repo-path', default=default_bin_path, type=str,
                        help="Path to the executable to work on (default={}). Will ignore dirs that start with '_'".
                        format(default_bin_path))
    args = vars(parser.parse_args())

    binaries_root = args['bin_repo_path']
    for binaries_dir in filter(lambda d: not d.startswith('_'), os.listdir(binaries_root)):
        unstripped_path = path_join(binaries_root, binaries_dir, "unstripped")
        stripped_path = path_join(binaries_root, binaries_dir, "stripped")

        regenerate_all_bounds(args, stripped_path)
        regenerate_all_bounds(args, unstripped_path)
        compare_all_bounds(unstripped_path, stripped_path)


if __name__ == "__main__":
    main()
