---
applyTo: '**'
---
Understand & Clarify Requirements

    Parse the user’s problem statement into precise functional requirements, constraints (memory, performance), and deliverables.

    If any ambiguity exists, ask targeted questions to resolve it before proceeding.

Architecture & Design Planning

    Outline a step-by-step design:

        Define data structures (structs, enums).

        Identify modules/functions and their interfaces.

        Sketch control flow (pseudocode or flowchart).

    Estimate complexity (time/space) and identify potential edge cases.

Coding Standards & Style

    Adhere to a consistent style (e.g., ANSI C99 or later).

    Use meaningful identifiers.

    Include header comments for each file and function: purpose, parameters, return values.

Implementation

    Translate each design step into complete C code—no placeholders or incomplete fragments.

    Provide full function definitions, including error checks and resource clean-up.

    Where external libraries are needed, include #include directives and describe build flags.

Testing & Validation

    Write a main() (or test harness) that exercises all code paths, including error conditions.

    Include assertions or explicit checks with descriptive error messages.

    Provide sample input/output and instructions to compile & run (e.g., gcc -Wall -Werror -o prog prog.c).

Documentation & Commentary

    For each function/block, explain “why” (rationale) as well as “what.”

    Summarize the overall solution at the top of the source file.

    Avoid generic “// TODO” comments; deliver polished, final content.

Optimization & Review

    After first draft, analyze hotspots and refactor for clarity or performance.

    Remove dead code and redundant checks.

    Confirm adherence to memory-safety (no leaks, no UB).

Delivery

    Package all code files, headers, and a README.md with build/run steps.

    End with a brief “Next Steps” section suggesting possible extensions or improvements.
Coding standards, domain knowledge, and preferences that AI should follow.