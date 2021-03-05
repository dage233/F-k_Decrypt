#!/usr/bin/python
#
# Brainfuck Interpreter
# Copyright 2011 Sebastian Kaspari
#
# Usage: ./brainfuck.py [FILE]

import sys


class _Getch:
    """Gets a single character from standard input.  Does not echo to the
screen."""
    
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            self.impl = _GetchUnix()
    
    def __call__(self):
        return self.impl()


class _GetchUnix:
    def __init__(self):
        import tty, sys
    
    def __call__(self):
        import sys, tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


class _GetchWindows:
    def __init__(self):
        import msvcrt
    
    def __call__(self):
        import msvcrt
        return msvcrt.getch()


getch = _Getch()


def brainfuck(code):
    out=''
    code = cleanup(list(code))
    bracemap = buildbracemap(code)
    
    cells, codeptr, cellptr = [0], 0, 0
    
    while codeptr < len(code):
        command = code[codeptr]
        
        if command == ">":
            cellptr += 1
            if cellptr == len(cells): cells.append(0)
        
        if command == "<":
            cellptr = 0 if cellptr <= 0 else cellptr - 1
        
        if command == "+":
            cells[cellptr] = cells[cellptr] + 1 if cells[cellptr] < 255 else 0
        
        if command == "-":
            cells[cellptr] = cells[cellptr] - 1 if cells[cellptr] > 0 else 255
        
        if command == "[" and cells[cellptr] == 0: codeptr = bracemap[codeptr]
        if command == "]" and cells[cellptr] != 0: codeptr = bracemap[codeptr]
        if command == ".": out+=(chr(cells[cellptr]))
        if command == ",": cells[cellptr] = ord(getch())
        
        codeptr += 1
    return out


def cleanup(code):
    return ''.join(filter(lambda x: x in ['.', ',', '[', ']', '<', '>', '+', '-'], code))


def buildbracemap(code):
    temp_bracestack, bracemap = [], {}
    
    for position, command in enumerate(code):
        if command == "[": temp_bracestack.append(position)
        if command == "]":
            start = temp_bracestack.pop()
            bracemap[start] = position
            bracemap[position] = start
    return bracemap


def ook(code):
    lookup = {
        '.?': '>',
        '?.': '<',
        '..': '+',
        '!!': '-',
        '!.': '.',
        '.!': ',',
        '!?': '[',
        '?!': ']',
    }
    str2 = code.replace('\n', '').replace('Ook', '').replace(' ', '')
    lenth = len(str2)
    cs = ''
    for i in range(0, lenth, 2):
        cs += lookup[str2[i] + str2[i + 1]]
    return brainfuck(cs)


def main():
    print('Test')
    brainfuck('''+++++ +++++ [->++ +++++ +++<] >++.+ +++++ .<+++ [->-- -<]>- -.+++ +++.<
++++[ ->+++ +<]>+ +++.< +++++ [->-- ---<] >.<++ ++[-> ++++< ]>+++ .<+++
[->-- -<]>- ----. ++++. <+++[ ->+++ <]>+. <++++ [->-- --<]> ----- -.<++
+[->+ ++<]> ++.-. ----- ---.< +++[- >+++< ]>+++ .---- .<+++ [->-- -<]>-
.<+++ +++[- >---- --<]> ----- ----. +.<++ +++++ +[->+ +++++ ++<]> +++++
+++++ .<''')


if __name__ == "__main__": main()
