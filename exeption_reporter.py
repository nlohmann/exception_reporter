#!/usr/bin/env python3

import re
import sys
from typing import Dict, List, Optional


class Callgraph:
    def __init__(self):
        self.nodes = {}  # type: Dict[str, List[str]]

    def add_edge(self, node_from: str, node_to: str):
        if node_from not in self.nodes:
            self.nodes[node_from] = []

        # avoid duplicates
        if node_to not in self.nodes[node_from]:
            self.nodes[node_from].append(node_to)

    def direct_successors(self, node_from: str) -> List[str]:
        return self.nodes.get(node_from, [])

    def indirect_successors(self, node_from: str) -> List[str]:
        # start with direct successors
        reachable_nodes = [x for x in self.direct_successors(node_from)]

        # iteratively add direct successors until no new node is found
        result_changed = True
        while result_changed:
            result_changed = False
            for node in reachable_nodes:
                for successor_node in self.direct_successors(node):
                    if successor_node not in reachable_nodes:
                        reachable_nodes.append(successor_node)
                        result_changed = True

        return reachable_nodes


def parse(filename: str) -> Callgraph:
    def unquote(s: str) -> str:
        quoted = re.compile('"[^"]*"')
        return quoted.findall(s)[0][1:-1]

    def get_called_function(s: str) -> str:
        try:
            _, name = s.split(' calls function ')
            return unquote(name)
        except ValueError:
            return 'external'

    def get_function_name(s: str) -> Optional[str]:
        try:
            _, name = s.split('Call graph node for function: ')
            name, _ = name.split('  #uses')
            return unquote(name)
        except ValueError:
            # this should only happen at the root node
            return None

    function_name = None
    cg = Callgraph()

    with open(filename) as f:
        for line in f.readlines():
            if 'Call graph node' in line:
                # we found a new node - remember the name as this is the source for subsequent calls
                function_name = get_function_name(line.strip())
            elif '> calls ' in line:
                # we found a call line

                if function_name is None:
                    continue

                called_function_name = get_called_function(line.strip())
                # add the functions in reverse relation so we can quickly find who called which function later
                cg.add_edge(called_function_name, function_name)

    return cg


def analyze(cg: Callgraph):
    exception_types =  ['logic_error', 'domain_error', 'invalid_argument', 'length_error', 'out_of_range', 'runtime_error', 'range_error', 'overflow_error', 'underflow_error']

    print('\nfunctions containing a throw:')
    for fn in cg.direct_successors('__cxa_throw'):
        print('-', fn)

    for exception_type in exception_types:
        thrower_name = 'std::{exception_type}::{exception_type}(char const*)'.format(exception_type=exception_type)
        funs = set(cg.direct_successors('__cxa_throw')).intersection(set(cg.indirect_successors(thrower_name)))

        if len(funs):
            print('\nfunctions that MAY throw std::{exception_type}:'.format(exception_type=exception_type))
            for fn in funs:
                print('-', fn)

    print('\nfunctions that MAY encounter an exception:')
    for fn in cg.indirect_successors('__cxa_throw'):
        print('-', fn)

    for exception_type in exception_types:
        thrower_name = 'std::{exception_type}::{exception_type}(char const*)'.format(exception_type=exception_type)
        funs = set(cg.indirect_successors('__cxa_throw')).intersection(set(cg.indirect_successors(thrower_name)))

        if len(funs):
            print('\nfunctions that MAY encounter a std::{exception_type} exception:'.format(exception_type=exception_type))
            for fn in funs:
                print('-', fn)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        analyze(parse(sys.argv[1]))
    else:
        print('Usage: {tool} callgraph.txt'.format(tool=sys.argv[0]))
        sys.exit(1)
