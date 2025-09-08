# MBA-Simplifier

![Screenshot](https://github.com/mojtabafalleh/MBA-Simplifier/blob/master/docs/Screenshot%202025-09-06%20210256.png)

**MBA-Simplifier** is a simple tool designed to analyze and break MBA (Mixed Boolean-Arithmetic) code.  

It takes a hex string representing assembly instructions, emulates the code, and then attempts to guess the original instructions.

## Features

- Fast assembly emulation using Unicorn Engine.
- Tracks register changes and memory accesses.
- Attempts to guess instructions such as `mov`, `add`, `sub`, `xor`, `push`, `pop`, and other basic instructions.
- Shows results in the console with colors: green for correct guesses, red for mismatches.
- Displays the machine code of guessed instructions.
- Provides a memory access log for analysis.

## Usage

You can run the tool with a hex string as input:

```bash
MBA-Simplifier.exe 41 53 4C 31 DB 49 31 CB 4C 31 DB 41 5B
```
## Example output:
```bash
[Best guess after 10 trials]: xor RBX,RCX
[OK] xor RBX,RCX behaves same as original.
Machine code: 48 31 CB

--- Memory accesses ---
[WRITE] 0x16a46c8fe val=0x17a2a5ca7 reg value : R11
[READ] 0x16a46c8fe val=0x17a2a5ca7 reg value : R11
```
## Notes

- This is currently a **prototype**. More instruction types and advanced patterns may be supported in future updates.
- Designed to simplify analysis of MBA-protected code and assist in reverse engineering tasks.
