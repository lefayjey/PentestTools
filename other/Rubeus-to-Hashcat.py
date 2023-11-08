#!/usr/bin/env python3

import string, argparse, re

class Logger:

    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    @staticmethod
    def info(message):
        print("[%s*%s] %s" % (Logger.BLUE, Logger.ENDC, message))

    @staticmethod
    def success(message):
        print("[%s+%s] %s" % (Logger.GREEN, Logger.ENDC, message))

    @staticmethod
    def failure(message):
        print("[%s-%s] %s" % (Logger.RED, Logger.ENDC, message))


def create_arg_parser():
    parser = argparse.ArgumentParser(description="Tool to convert Rubeus kerberoast hashes into hashcat format")
    parser.add_argument('-i', "--input", help="Input file containing Rubeus kerberoast output", required=True)
    parser.add_argument('-o', "--output", help="File to output the parsed hashes too", required=True)
    return parser


def rubeus_to_hashcat(input, output):
    gtfo = ["SamAccountName", "DistinguishedName", "ServicePrincipalName", "PwdLastSet", "Supported ETypes"]

    infile = open(input, "rt")
    outfile = open(output, "wt")

    files = infile.readlines()

    for line in files:
        if any(x in line for x in gtfo):
            pass
        else:
            line = re.sub(r"[\n\t\s]*", "", line)
            line = line.split(':',1)[-1]
            line = line.replace("$krb", "\n$krb")
            outfile.write(line)
            outfile.close


def main():
    parser = create_arg_parser()
    args = parser.parse_args()

    if args is not None:
        Logger.info("Input file is %s" % args.input)
        Logger.info("Output file is %s" % args.output)
        rubeus_to_hashcat(args.input, args.output)
        Logger.success("Hashes converted, happy cracking!")
    else:
        Logger.failure("Invalid arguments")
        parser.print_help()


if __name__ == "__main__":
    main()
