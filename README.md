# linuxscorer

A template Linux scorebot and TUI, a natural evolution of [linuxtrainer](//github.com/sebasterisk/linuxtrainer), using [Textual](//textual.textualize.io/) to display score reports directly in the terminal. Used to check if system vulnerabilities or other issues are addressed and/or fixed in cybersecurity training images. Coded in Python, of course. 

## feature set
*linuxscorer*'s vulnclasses file includes a few helpful classes to create scored vulnerabilities. You can include vuln descriptions and point values to be displayed in the score report. It is also possible for one vulnerability to require multiple issues to be fixed. 

The `Answer` class is an issue that is checked when a `Vuln` is graded. You can check for substrings or regular expressions in a file, or if a filepath exists or not. The `Vuln` class then checks if all the `Answer`s are addressed correctly, and the `VulnList` class then checks which `Vuln`s have been fully resolved. The score report is then created in the main file and shown to the end user. 

| Score type                                   | Answer "type" string | Requires `checking_for` | Requires `in_path` |
|----------------------------------------------|----------------------|-------------------------|--------------------|
| Check if file exists                         | `"path_exist"`       |    | ✓ |
| Check if file doesn't exist                  | `"path_not_exist"`   |    | ✓ |
| Check if file has text                       | `"substr_in_file"`   | ✓ | ✓ |
| Check if file doesn't have text              | `"substr_not_file"`  | ✓ | ✓ |
| Check if file has text that matches regex    | `"regex_match_file"` | ✓ | ✓ |
| Check if file has no text that matches regex | `"regex_miss_file"`  | ✓ | ✓ |

## how to use
1. Download the repository and it's dependents in the requirements file into somewhere safe, such as in /etc. You may also find it useful to create a venv.
```
pip install -r .../requirements.txt
```

2. Add the vulns you want to check by editing main.py's `Module` class in the `VULNS` table. 
3. Obfuscate main.py using something like [pyarmor](https://github.com/dashingsoft/pyarmor), to make it difficult to recover answers.
4. Create an alias to run the script in ~/.bashrc, like
```
alias score="python3 .../main.py"
```
Additionally, you can create a `.desktop` entry file on the desktop to run the script directly from there.
Make sure to set `Terminal=true`.

5. Have fun?
