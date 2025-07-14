import subprocess
from enum import *
from pathlib import Path as path
import re

class CheckType(Enum):
    """
    Enumerations that are used when initializing an `Answer` class to determine how it will be checked for completion.
    """

    STRING_FOUND = "substr_in_file"
    """
    Check if `checking_for` is found anywhere in the file `path`.
    """
    STRING_NOT_FOUND = "substr_not_file"
    """
    Check if `checking_for` is not found anywhere in the file `path`.
    """
    REGEX_MATCHES = "regex_match_file"
    """
    Check if the regular expression `checking_for` is matched in any line in the file `path`.
    """
    REGEX_NO_MATCH = "regex_miss_file"
    """
    Check if the regular expression `checking_for` is not matched in any line in the file `path`.
    """
    PATH_EXISTS = "path_exist"
    """
    Check if the `path` exists anywhere on the system.
    """
    PATH_GONE = "path_not_exist"
    """
    Check if the `path` is not on the system.
    """
    PERMS_OCTAL = "perm_check"
    """
    Check if the `path`'s permission octal (three- or four-digit number) matches `checking_for`.
    """
    OWNER = "user_own_check"
    """
    Check if the `path`'s owner username matches `checking_for`.
    """
    GROUP = "group_own_check"
    """
    Check if the `path`'s owner group name matches `checking_for`.
    """
    SERVICE_UP = "service_up"
    """
    Check if the service `checking_for` is up according to systemd.
    """
    SERVICE_DOWN = "service_down"
    """
    Check if the service `checking_for` is down according to systemd.
    """
    STRING_FOUND_CMD_STDOUT = "substr_stdout"
    """
    Check if the standard output of the command includes `checking_for`
    """
    STRING_NOT_FOUND_CMD_STDOUT = "substr_stdout"
    """
    Check if the standard output of the command does not include `checking_for`
    """

class Answer():
    def __init__(
            self,                                
            type: CheckType,
            checking_for: str | None = None, 
            in_path: path | None = None,
            path_gone_ok: bool = False,
            command_to_run: str | None = None
        ):

        self.type = type
        self.checking_for = checking_for
        self.path = in_path
        self.path_gone_ok = path_gone_ok
        self.command_to_run = command_to_run
    
    def in_f_find(self, string: str, regex: bool, filepath: path):
        if regex:
            compiled_regex = re.compile(string)
            if not filepath.exists(): return False

            with filepath.open() as file:
                for i, line in enumerate(file):
                    if len(re.findall(compiled_regex, line)) > 0: return True 
                        
        else:
            with filepath.open() as file:
                if string in file.read(): return True

            return False
        
        return False

    def check_answer(self):
        checking_for_exists = isinstance(self.checking_for, str)
        path_obj_exists = isinstance(self.path, path)
        custom_command_exists = isinstance(self.command_to_run, path)
        

        path_paved = self.path.exists() if path_obj_exists else False

        if (self.path_gone_ok) and (not path_paved): 
            return True
        elif (not self.path_gone_ok) and (not path_paved):
            return False
        
        match self.type:
            case CheckType.STRING_FOUND:      # is checking_for in the file?    
                if not (checking_for_exists and path_obj_exists): return False
                return self.in_f_find(self.checking_for, False, self.path)
            # --~----~----~----~--
            case CheckType.STRING_NOT_FOUND:     # is checking_for NOT in the file?
                if not (checking_for_exists and path_obj_exists): return False
                return not self.in_f_find(self.checking_for, False, self.path)
            # --~----~----~----~--
            case CheckType.REGEX_MATCHES:    # is the regex in checking_for matched anywhere in the file?
                if not (checking_for_exists and path_obj_exists): return False
                return self.in_f_find(self.checking_for, True, self.path)
            # --~----~----~----~--
            case CheckType.REGEX_NO_MATCH:     # is the regex in checking_for never found in the file
                if not (checking_for_exists and path_obj_exists): return False
                return not self.in_f_find(self.checking_for, True, self.path)
            # --~----~----~----~--
            case CheckType.PATH_EXISTS:          # does the path exist?
                if not (path_obj_exists): return False
                return self.path.exists()
            # --~----~----~----~--
            case CheckType.PATH_GONE:      # does the path not exist?
                if not (path_obj_exists): return False
                return not self.path.exists()
            # --~----~----~----~--
            case CheckType.PERMS_OCTAL:          # does the permission octal match?
                if not (checking_for_exists and path_obj_exists): return False
                result = subprocess.run(["stat", r"-c '%a'", self.path.as_posix()], capture_output=True, encoding="utf-8")
                return self.checking_for in result.stdout
            # --~----~----~----~--
            case CheckType.OWNER:       # does the file owner username match checking_for?
                if not (checking_for_exists and path_obj_exists): return False
                result = self.path.owner()
                return result == self.checking_for
            # --~----~----~----~--
            case CheckType.GROUP:       # does the file owner gid match checking_for?
                if not (checking_for_exists and path_obj_exists): return False
                result = self.path.group()
                return result == self.checking_for
            # --~----~----~----~--
            case CheckType.SERVICE_UP:          # is the SystemV service active?
                if not (checking_for_exists): return False
                result = subprocess.call(["systemctl", "is-active", "--quiet", self.checking_for])
                if result != 0:
                    return False
                return True
            case CheckType.SERVICE_DOWN:
                if not (checking_for_exists): return False
                result = subprocess.call(["systemctl", "is-active", "--quiet", self.checking_for])
                if result != 0:
                    return True
                return False
            case CheckType.STRING_FOUND_CMD_STDOUT:
                if not (checking_for_exists and custom_command_exists): return False
                result = subprocess.run([self.command_to_run], capture_output=True, encoding="utf-8")
                return self.checking_for in result.stdout

class Vuln():
    def __init__(
            self, 
            *answer: Answer, 
            points: int = 0,
            desc: str = "Vulnerability Solved",
            order: int = 0,
        ):

        self.answer = answer
        self.points = points
        self.desc = desc
        self.order = order
    
    def check_full_solved(self) -> bool:
        for i,v in enumerate(self.answer):
            result = v.check_answer()
            if not result: 
                return False
        
        return True
    
class VulnList():
    def __init__(
            self,
            vulns: list[Vuln]
        ):
        self.vulns = vulns

    def get_completed_vulns(self, sort_by_order: bool = True) -> list[Vuln]:
        completed_vulns = []
        for v in self.vulns:
            if v.check_full_solved():
                completed_vulns.append(v)
        
        if sort_by_order:
            completed_vulns.sort(key = lambda x: x.order)
    
        return completed_vulns
    
    def get_completed_vuln_score(self) -> int:
        list = self.get_completed_vulns()
        return sum(x.points for x in list)
    
    def get_total_points(self) -> int:
        return sum(x.points for x in self.vulns)