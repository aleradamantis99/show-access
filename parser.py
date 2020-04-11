#!/usr/bin/python3.7m

import argparse
import re

def _ip_type (s, pat=r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"):
    if not re.match(pat, s):
        raise argparse.ArgumentTypeError("Formato de IP incorrecto")
    return s

def parse_arguments():
    parser = argparse.ArgumentParser(prog="Packets", description="Tool for sending packets")
    
    TargetArguments = parser.add_argument_group("Targets")
    TargetArguments.add_argument("-A", "--target1", type=_ip_type, required=True)
    
    SecondTargetGroup = TargetArguments.add_mutually_exclusive_group(required=True)
    SecondTargetGroup.add_argument("-B", "--target2", type=_ip_type)
    SecondTargetGroup.add_argument("-g", "--gateway", action="store_true", dest="UseGateway", help="Use gateway as B (target2)") 
    
    AttackArguments = parser.add_argument_group("Attack modes")
    AttackArguments.add_argument ("-D", "--DNS", help="Blocks all traffic and only shows DNS requests")
    AttackArguments.add_argument ("-M", "--MITM", help="Performs MITM")
    
    
    parser.add_argument("-o", "--oneway", action="store_true", help="Poison A (target1) only")
    
    return parser.parse_args()
    
if __name__ == "__main__":
    print (parse_arguments())
