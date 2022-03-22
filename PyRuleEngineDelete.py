import argparse
import json
import sys

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

    def count_delete(self, string: str, indices, f_out):
        for idx in indices:
            rule = self.rules[idx]
            word = string
            has_D = any(function[0] in count_func_map for function in rule)
            if not has_D:
                continue
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
        for line in f_log:
            line = line.strip('\r\n')
            word, rule_ids = json.loads(line)
            engine.count_delete(word, rule_ids, f_out)
            pass
        pass
    pass


if __name__ == '__main__':
    wrapper()
    pass
