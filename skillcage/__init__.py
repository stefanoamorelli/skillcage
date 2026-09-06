"""skillcage — detonate an untrusted agent skill in a rootless sandbox.

The skill runs headless inside a locked container. It never holds your model key
(a proxy injects it), every other network attempt is denied and logged, and what
the skill reaches for is diffed against what it declared. Rootless, no added
capabilities, one command.
"""
__version__ = "0.1.0"
