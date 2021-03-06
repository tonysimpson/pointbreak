[![Build Status](https://travis-ci.com/tonysimpson/pointbreak.svg?branch=master)](https://travis-ci.com/tonysimpson/pointbreak)
# Pointbreak 

Pointbreak lets you write python programs that debug or analysis other programs. It works like a debugger but because it's a Python library you can extend and interact with it very easily.

Pointbreak is designed to make debugging and analysing complex things like JITs simpler without having to added lots of debugging code to the target.

[Europython 2018 lightning talk](https://www.youtube.com/watch?v=czHfx2MVch0)

## General Advantages
* Breakpoints are any Python callable
* Simple API
* Can be used from a Python REPL like IPython
* Can be easily embedded in other things e.g. a Flask app
* Easy to add support for custom symbols and JIT generated code
* Simpler and less restrictive than GDB Python API

## Disadvantage
* Early development
* Missing many standard debugger features
* Other issues see https://github.com/tonysimpson/pointbreak/issues

# Example print BOO! when function is called
If you compile `gcc ghost.c -o ghost` and run `./ghost` nothing much happens
But if we run `python boo_ghost.py` it prints
```Boo!
Boo!
Boo!
Boo!
Boo!
Boo!
Boo!
Boo!
Boo!
Boo!
```
because our python function is getting called each time there_is_a_ghost is called.
There are more examples in the examples directory.

## ghost.c
```C
/* I'm a silly program that does nothing much on its own. */
/* Compile me with "gcc ghost.c -o ghost".                */

void there_is_a_ghost(void) {
    return;
}

int main(int argc, char *argv[]) {
    int i;
    for (i = 0; i < 10; i++) {
        there_is_a_ghost();
    }
    return 0;
}
```
## boo_ghost.py
```python
from __future__ import print_function
import pointbreak

def print_boo(debugger):
    print("Boo!")
    return True

db = pointbreak.create_debugger('ghost')
db.add_breakpoint('there_is_a_ghost', print_boo)
db.continue_to_last_event()
```
