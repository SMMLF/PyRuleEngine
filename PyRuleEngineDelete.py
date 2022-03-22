import argparse
import json
import sys
from json import JSONDecodeError 

from PyRuleEngine import RuleEngine, function_map, i36

del_keys = set("lucC[]DxOo'@MX46")


def count_l(word, indices):
    msg = []
    for i, c in enumerate(word):
        if c.isupper():
            msg.append(f"{i}\t{c}")
    return 'l\t' + '\t'.join(msg)


def count_u(word, indices):
    msg = []
    for i, c in enumerate(word):
        if c.islower():
            msg.append(f"{i}\t{c}")
    return 'u\t' + '\t'.join(msg)


def count_D(word, indices):
    n, = indices
    n = i36(n)
    if n >= len(word):
        return ""
    return f"D\t{n}\t{word[n]}\n"


count_func_map = {
    'D': count_D,
}


class RuleEngineDelete(RuleEngine):
    def __init__(self, rules=None, rejected_rules=None):
        super().__init__(rules, rejected_rules)
        self.not_ok = set()
        for rule_id, rule in enumerate(self.rules):
            has_D = any(function[0] in count_func_map for function in rule)
            if not has_D:
                self.not_ok.add(rule_id)

    def count_delete(self, string: str, indices, f_out):
        for idx in indices:
            if idx in self.not_ok:
                continue
            rule = self.rules[idx]
            word = string
            
            for function in rule:
                try:
                    key = function[0]
                    remain = function[1:]
                    if key in count_func_map:
                        fk = count_func_map[key]
                        res = fk(word, remain)
                        f_out.write(res)
                    func = function_map[key]
                    word = func(word, remain)
                except IndexError:
                    """"""
        pass

    pass


def wrapper():
    cli = argparse.ArgumentParser('Check delete')
    cli.add_argument('-l', '--log', dest='log', required=True, help='read log file')
    cli.add_argument('-s', '--save', dest='save', help='save result')
    args = cli.parse_args()
    log_file, save_file = args.log, args.save
    if save_file is not None:
        f_out = open(save_file, 'w')
    else:
        f_out = sys.stdout
    with open(log_file, 'r') as f_log:
        meta_line = f_log.readline().strip('\r\n')
        meta = json.loads(meta_line)

        rules = meta['rules']
        engine = RuleEngineDelete(rules=rules, rejected_rules=None)
        line_cnt = 1
        for line in f_log:
            line = line.strip('\r\n')
            line_cnt += 1
            word, rule_ids = json.loads(line)
            engine.count_delete(word, rule_ids, f_out)
            if line_cnt % 10000 == 0:
                print(f"{line_cnt}", end='\r', flush=True, file=sys.stderr)
            pass
        pass
    pass


if __name__ == '__main__':
    try:
        wrapper()
    except JSONDecodeError:
        print('over')
    pass
