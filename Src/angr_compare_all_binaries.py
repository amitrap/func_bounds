import os
from os.path import join as path_join
import re
import angr
import argparse

BINARIES_NAME_PATTERN = "^.*"


def gen_blocks_addr_set(elf_path):
    proj = angr.Project(elf_path, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFG()
    funcs_basic_blocks_dict = {func: proj.kb.functions[func].block_addrs for func in proj.kb.functions.keys()}
    return frozenset({k: frozenset(funcs_basic_blocks_dict[k]) for k in funcs_basic_blocks_dict.keys()}.items())


def compare_all_bounds(unstripped_dir_path, stripped_dir_path):
    undiscovered_count = 0
    unstripped_count = 0

    # Construct a binaries list containing only desired names
    binaries_list = []
    dirpath, dirnames, filenames = os.walk(unstripped_dir_path).next()
    for name in filenames:
        if name.endswith(r".bounds.auto.py") or not re.match(BINARIES_NAME_PATTERN, name):
            continue
        binaries_list.append(name)

    # Iterate all binaries, generate sets of basic blocks and compares between stripped+unstripped versions
    i = 0
    for name in binaries_list:
        i = i + 1
        unstripped_file_path = os.path.join(unstripped_dir_path, name)
        stripped_file_path = os.path.join(stripped_dir_path, name)

        print "(%d/%d) Parsing bounds for unstripped=%s stripped=%s" % (
        i, len(binaries_list), unstripped_file_path, stripped_file_path)

        stripped_set = gen_blocks_addr_set(stripped_file_path)
        unstripped_set = gen_blocks_addr_set(unstripped_file_path)
        undiscovered_func_bounds = frozenset(unstripped_set) - frozenset(stripped_set)

        unstripped_count += len(unstripped_set)
        undiscovered_count += len(undiscovered_func_bounds)
        print 'current: undiscovered funcs count = %d, total funcs count = %d' % (undiscovered_count, unstripped_count)
    print 'Results for files with pattern "%s" is: (undiscovered count/func count) (%d/%d), %f%%' % (
    BINARIES_NAME_PATTERN, undiscovered_count, unstripped_count, (float(undiscovered_count) / unstripped_count) * 100.0)


def main():
    parser = argparse.ArgumentParser(description="Evaluate Angr.io's ability to detect stripped procedures.")
    default_bin_path = "../Data" if os.getcwd().endswith('Src') else "Data"
    parser.add_argument('--bin-repo-path', default=default_bin_path, type=str,
                        help="Path to the executable to work on (default={}). Will ignore dirs that start with '_'".
                        format(default_bin_path))
    args = vars(parser.parse_args())

    binaries_root = args['bin_repo_path']
    for binaries_dir in filter(lambda d: not d.startswith('_'), os.listdir(binaries_root)):
        unstripped_path = path_join(binaries_root, binaries_dir, "unstripped")
        stripped_path = path_join(binaries_root, binaries_dir, "stripped")

        compare_all_bounds(unstripped_path, stripped_path)


if __name__ == "__main__":
    main()
