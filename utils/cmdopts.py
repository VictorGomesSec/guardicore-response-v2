# Copyright Lumu Technologies

"""Command line utilities shared by command line tools & unit tests."""

from __future__ import absolute_import
from __future__ import print_function

import sys
from argparse import ArgumentParser, Action
from os import path

__all__ = ["error", "ConfigAction", "Parser", "cmdline"]


# Print the given message to stderr, and optionally exit
def error(message, exitcode=None):
    print("Error: %s" % message, file=sys.stderr)
    if exitcode is not None:
        sys.exit(exitcode)


class record(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


# Custom action
class ConfigAction(Action):
    """
    Custom Action to load configuration from file
    """

    def __call__(self, parser, namespace, values, option_string=None):
        parser.load(values[0])


class Parser(ArgumentParser):
    def __init__(self, rules=None, **kwargs):
        ArgumentParser.__init__(self, **kwargs)
        self.dests = set({})
        self.result = record({"args": [], "kwargs": record()})
        if rules is not None:
            self.init(rules)

    def init(self, rules):
        """Initialize the parser with the given command rules."""
        # Initialize the option parser
        for dest in rules.keys():
            rule = rules[dest]

            # Assign defaults ourselves here, instead of in the option parser
            # itself in order to allow for multiple calls to parse (dont want
            # subsequent calls to override previous values with default vals).
            if "default" in rule:
                self.result["kwargs"][dest] = rule["default"]

            flags = rule["flags"]
            kwargs = {"action": rule.get("action", "store")}
            # NOTE: Don't provision the parser with defaults here, per above.
            # Added choices for handling type choice
            for key in [
                "callback",
                "help",
                "metavar",
                "type",
                "choices",
                "default",
                "required",
                "nargs",
            ]:
                if key in rule:
                    kwargs[key] = rule[key]
            self.add_argument(*flags, dest=dest, **kwargs)

            # Remember the dest vars that we see, so that we can merge results
            self.dests.add(dest)

    # Load command options from given 'config' file. Long form options may omit
    # the leading "--", and if so we fix that up here.
    def load(self, filepath):
        argv = []
        try:
            file = open(filepath)
        except:
            error("Unable to open '%s'" % filepath, 2)
        for line in file:
            if line.startswith("#"):
                continue  # Skip comment
            line = line.strip()
            if len(line) == 0:
                continue  # Skip blank line
            if not line.startswith("-"):
                line = "--" + line
            argv.append(line)
        self.parse(argv)
        return self

    def loadif(self, filepath):
        """Load the given filepath if it exists, otherwise ignore."""
        if path.isfile(filepath):
            self.load(filepath)
        return self

    def loadrc(self, filename):
        filepath = path.join(
            path.dirname(path.dirname(path.join(path.abspath(__file__)))), filename
        )
        self.loadif(filepath)
        return self

    def parse(self, argv):
        """Parse the given argument vector."""
        kwargs = vars(self.parse_args(argv))
        for dest in self.dests:
            value = kwargs.get(dest, None)
            if value is not None:
                self.result["kwargs"][dest] = value
        return self

    def format_epilog(self, formatter):
        return self.epilog or ""

    def kwargs_as_list(self):
        """Returns kwargs as list of args like argv"""
        argv = []
        for k, v in self.result.get("kwargs", []).items():
            if isinstance(v, list):
                for item in v:
                    argv.append("--" + k)
                    argv.append(str(item))
            elif not isinstance(v, bool):
                argv.append("--" + k)
                argv.append(str(v))
        return argv


def cmdline(argv, rules=None, config=None, **kwargs):
    """Simplified cmdopts interface that does not default any parsing rules
    and that does not allow compounding calls to the parser."""
    parser = Parser(rules, **kwargs)
    if config is not None:
        parser.loadrc(config)
    return parser.parse(argv).result
