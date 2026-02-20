# Challenge Analysis: virtually.mad

## Overview

**Category:** Reverse Engineering  
**Difficulty:** Medium  
**Format:** HTB (Hack The Box)

This challenge presents a custom binary that acts as a small virtual machine (VM). Your goal is to figure out what input the machine expects — and craft it precisely.

---

## What You're Given

A single ELF 64-bit binary with an unusual extension (`.mad`). It prompts you to enter a "code to execute" and either accepts or rejects your input.

---

## Core Concepts Involved

### 1. Binary Analysis
Before doing anything else, you'll want to examine the binary with standard tools. Checking the file type, extracting readable strings, and inspecting the structure will reveal important clues about what the program expects and how it works internally.

### 2. Virtual Machine Architecture
The binary implements a minimalist virtual machine from scratch. This is a classic reverse engineering pattern where:
- The program defines its own set of **registers**
- It implements its own **instruction set** (opcodes)
- It interprets and executes a sequence of instructions provided as input

Understanding the VM's architecture — how many registers there are, what instructions exist, and how they're encoded — is the heart of the challenge.

### 3. Instruction Encoding
Each instruction is encoded as a fixed-size value. Part of your job is to reverse-engineer the **bit layout** of each opcode: which bits represent the instruction type, which represent operands, and which represent modes or flags.

### 4. Winning Condition
The VM performs a series of operations on its registers and then checks whether the final machine state matches a specific expected value. You need to understand:
- What the final state must look like
- What sequence of instructions can produce that state
- What constraints exist on the instructions you can use

### 5. Constraint Solving
This isn't just about finding *any* program that reaches the target state — the binary also **validates the structure** of your input before executing it. Each instruction must conform to specific format rules. You'll need to satisfy both the structural constraints *and* the semantic goal simultaneously.

---

## Skills You'll Practice

- Static binary analysis (disassembly, string extraction)
- Understanding custom instruction set architectures
- Bit manipulation and opcode decoding
- Working backward from a goal state to construct a valid input
- Attention to boundary conditions (e.g., value range checks)

---

## Approach Hints (No Spoilers)

- Start by running the binary and observing its behavior with different inputs.
- Disassemble the binary and look for the main logic loop — it will reveal the VM's dispatch mechanism.
- Map out the instruction types one by one before trying to craft a solution.
- Pay close attention to **validation** checks separate from **execution** — the binary enforces both.
- Think carefully about the order of operations when working backward from the desired final state.

---

## Key Takeaway

This challenge is a great introduction to **VM-based reversing**, a technique frequently used in real-world software protection (obfuscation, anti-tamper, licensing systems). The ability to reconstruct an undocumented instruction set from disassembly alone is a fundamental skill in reverse engineering.
