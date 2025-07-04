import subprocess
from pathlib import Path as path
import re

class Answer():
    def __init__(
            self,                                
            type: str,
            checking_for: str | None = None, 
            in_path: path | None = None
        ):

        self.type = type
        self.checking_for = checking_for
        self.path = in_path
    
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
        path_exists = isinstance(self.path, path)

        match self.type:
            case "substr_in_file":      # is checking_for in the file?    
                if not (checking_for_exists and path_exists): return False
                return self.in_f_find(self.checking_for, False, self.path)
            # --~----~----~----~--
            case "substr_not_file":     # is checking_for NOT in the file?
                if not (checking_for_exists and path_exists): return False
                return not self.in_f_find(self.checking_for, False, self.path)
            # --~----~----~----~--
            case "regex_match_file":    # is the regex in checking_for matched anywhere in the file?
                if not (checking_for_exists and path_exists): return False
                return self.in_f_find(self.checking_for, True, self.path)
            # --~----~----~----~--
            case "regex_miss_file":     # is the regex in checking_for never found in the file
                if not (checking_for_exists and path_exists): return False
                return not self.in_f_find(self.checking_for, True, self.path)
            # --~----~----~----~--
            case "path_exist":          # does the path exist?
                if not (path_exists): return False
                return self.path.exists()
            # --~----~----~----~--
            case "path_not_exist":      # does the path not exist?
                if not (path_exists): return False
                return not self.path.exists()
            # --~----~----~----~--
            case "perm_check":          # does the permission octal match?
                if not (checking_for_exists and path_exists): return False
                result = subprocess.run(["stat", r"-c '%a'", self.path.as_posix()], capture_output=True, encoding="utf-8")
                return self.checking_for in result.stdout
            # --~----~----~----~--
            case "user_own_check":       # does the file owner username match checking_for?
                if not (checking_for_exists and path_exists): return False
                result = self.path.owner()
                return result == self.checking_for
            # --~----~----~----~--
            case "group_own_check":       # does the file owner gid match checking_for?
                if not (checking_for_exists and path_exists): return False
                result = self.path.group()
                return result == self.checking_for
            # --~----~----~----~--
            case "service_up":          # is the SystemV service active?
                if not (checking_for_exists): return False
                result = subprocess.call(["systemctl", "is-active", "--quiet", self.checking_for])
                if result != 0:
                    return False
                return True

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