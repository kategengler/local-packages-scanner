# Scan your local machine for compromised packages

## Usage

`./scan-packages.sh compromised-packages.txt`

Very slow. No guarantees of correctness.

## Input (default: compromised-packages.txt)

A file with one package version per line:

```txt
foo@1.2.4
foo@1.2.5
```

## Output (default: findings-output.txt)

Will also output to console. 

