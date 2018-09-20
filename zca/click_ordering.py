from collections import OrderedDict
import click


# Thanks https://github.com/vlcinsky via https://github.com/pallets/click/issues/513#issuecomment-301046782
class NaturalOrderGroup(click.Group):
    """command group to list subcommands in the order they were added.
    Usage: @click.group(cls=NaturalOrderGroup)"""

    def __init__(self, name=None, commands={}, **attrs):
        commands = OrderedDict(commands)
        click.Group.__init__(self, name=name, commands=commands, **attrs)

    def list_commands(self, ctx):
        return self.commands.keys()
